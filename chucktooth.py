import os
import re
import pandas as pd
from openpyxl.utils import get_column_letter
from openpyxl.styles import PatternFill, Alignment, Font
from openpyxl.drawing.image import Image as ExcelImage
from datetime import datetime
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
import argparse
import matplotlib.pyplot as plt
import tempfile
from collections import defaultdict

PLACEHOLDER_VALUES = {
    "password", "token", "secret", "string", "null", "none", "default", "example", "changeme"
}

EXT_LANG_MAP = {
    '.py': 'Python', '.js': 'JavaScript', '.html': 'HTML', '.css': 'CSS',
    '.json': 'JSON', '.yml': 'YAML', '.yaml': 'YAML', '.ini': 'INI', '.cfg': 'CFG',
    '.c': 'C', '.cpp': 'C++', '.cc': 'C++', '.h': 'C/C++ Header', '.hpp': 'C++ Header',
    '.java': 'Java', '.rb': 'Ruby', '.go': 'Go', '.php': 'PHP', '.sh': 'Shell',
    '.bat': 'Batch', '.pl': 'Perl', '.swift': 'Swift', '.kt': 'Kotlin', '.ts': 'TypeScript'
}

def is_potential_secret(s):
    if not isinstance(s, str):
        return False
    s_lower = s.lower()
    if s_lower in PLACEHOLDER_VALUES:
        return False
    if len(set(s)) <= 3:
        return False
    if s.isdigit() or s.islower() or s.isupper():
        return False
    if len(s) < 8:
        return False
    return True

patterns = {
    "IP Address (IPv4)": r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b",
    "IP Address (IPv6)": r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b|\b::(?:[A-Fa-f0-9]{1,4}:){0,5}[A-Fa-f0-9]{1,4}\b",
    "Email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,7}\b",
    "Password/Token/Secret": r"""(?ix)
        \b(password|secret|pass(word)?|passwd|api_?key|token|access_token|client_secret|client_id)\b
        \s* (?:=|:)\s* 
        ['"]
        (?P<secret>[A-Za-z0-9!@#$%^&*()_+={}\[\]|;:<>,.?/~`-]{8,})
        ['"]
    """,
    "URL": r"\b(?:https?|ftp|file)://[^\s\"'><)]+",
    "Base64 Encoded": r"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b",
    "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
    "AWS Secret Key": r"\b(?:ASIA|AKIA)[A-Za-z0-9/+=]{16,40}\b",
    "Private Key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----[\s\S]+?-----END (RSA |EC |DSA )?PRIVATE KEY-----",
    "MongoDB URI": r"\bmongodb(?:\+srv)?:\/\/[^\s\"'<>]+",
    "Docker Credentials": r"//([A-Za-z0-9._-]+:[A-Za-z0-9!@#$%^&*()_+={}|;:<>,.?/~`-]{8,})@",
    "Generic Token": r"\b(?=[a-zA-Z0-9-_]{32,64}\b)(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z0-9-_]{32,64}\b"
}

pattern_flags = {
    "Password/Token/Secret": re.IGNORECASE | re.VERBOSE,
    "Private Key": re.DOTALL
}

def remove_illegal_excel_chars(val):
    if isinstance(val, str):
        return re.sub(r"[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]", "", val)
    return val

def scan_file(file_path):
    results = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, start=1):
                for key, pattern in patterns.items():
                    flags = pattern_flags.get(key, 0)
                    for match in re.finditer(pattern, line, flags):
                        if key == "Password/Token/Secret":
                            secret = match.group("secret")
                            if not is_potential_secret(secret):
                                continue
                            match_text = secret
                        elif key == "Docker Credentials":
                            match_text = match.group(1)
                            if not is_potential_secret(match_text.split(':', 1)[-1]):
                                continue
                        elif key == "Private Key":
                            continue
                        else:
                            match_text = match.group(0)
                        results.append({
                            'File': file_path,
                            'Line': i,
                            'Pattern': key,
                            'Match': match_text
                        })
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            priv_key_pattern = patterns["Private Key"]
            for match in re.finditer(priv_key_pattern, content, re.DOTALL):
                start_line = content[:match.start()].count('\n') + 1
                match_text = match.group(0)
                results.append({
                    'File': file_path,
                    'Line': start_line,
                    'Pattern': "Private Key",
                    'Match': match_text[:60] + ('...' if len(match_text) > 60 else '')
                })
    except Exception:
        pass
    return results

def scan_directory(directory):
    all_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.txt', '.py', '.js', '.html', '.json', '.env', '.yml', '.yaml', '.ini', '.cfg')) or '.' in file:
                all_files.append(os.path.join(root, file))
    results = []
    with ThreadPoolExecutor() as executor:
        for file_results in tqdm(executor.map(scan_file, all_files), total=len(all_files), desc="Scanning files"):
            results.extend(file_results)
    return results

def count_lines_per_language(directory):
    stats = defaultdict(int)
    for root, dirs, files in os.walk(directory):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            lang = EXT_LANG_MAP.get(ext)
            if lang:
                try:
                    with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                        stats[lang] += sum(1 for _ in f)
                except Exception:
                    continue
    if stats:
        df = pd.DataFrame(list(stats.items()), columns=["Language", "Lines of Code"])
        return df
    else:
        return pd.DataFrame(columns=["Language", "Lines of Code"])

def plot_loc_chart(df, img_path):
    if df is not None and not df.empty:
        plt.figure(figsize=(8, 5))
        plt.bar(df['Language'], df['Lines of Code'])
        plt.xticks(rotation=45, ha="right")
        plt.ylabel("Lines of Code")
        plt.title("Lines of Code by Language")
        plt.tight_layout()
        plt.savefig(img_path)
        plt.close()

def plot_findings_chart(results, img_path):
    df = pd.DataFrame(results)
    if not df.empty and 'Pattern' in df:
        count = df['Pattern'].value_counts()
        plt.figure(figsize=(8, 5))
        count.plot(kind="bar")
        plt.ylabel("Occurrences")
        plt.title("Sensitive Findings by Category")
        plt.tight_layout()
        plt.savefig(img_path)
        plt.close()

def save_to_excel(results, output_file, loc_df=None, loc_img=None, findings_img=None):
    df = pd.DataFrame(results)
    for col in df.columns:
        df[col] = df[col].map(remove_illegal_excel_chars)
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        # First Tab: Exec Summary with CONFIDENTIAL red banner
        if loc_df is not None and not loc_df.empty:
            loc_df.to_excel(writer, index=False, sheet_name='Exec Summary', startrow=1)
            workbook = writer.book
            worksheet = writer.sheets['Exec Summary']
            # RED CONFIDENTIAL BANNER (like Results tab)
            banner_text = f"CONFIDENTIAL // Seth K. Bates // {datetime.now().year}"
            worksheet.merge_cells(start_row=1, start_column=1, end_row=1, end_column=len(loc_df.columns))
            cell = worksheet.cell(row=1, column=1)
            cell.value = banner_text
            cell.fill = PatternFill(start_color="FF0000", end_color="FF0000", fill_type="solid")
            cell.alignment = Alignment(horizontal="center", vertical="center")
            cell.font = Font(bold=True, color="FFFFFF")
            # Set column widths for A and B
            worksheet.column_dimensions['A'].width = 22
            worksheet.column_dimensions['B'].width = 18
            # Insert LOC chart image
            if loc_img and os.path.exists(loc_img):
                img = ExcelImage(loc_img)
                img.anchor = f"A{len(loc_df)+4}"
                worksheet.add_image(img)
        # Tab 2: Sensitive Results
        df.to_excel(writer, index=False, sheet_name='Results', startrow=1)
        worksheet2 = writer.sheets['Results']
        banner_text = f"CONFIDENTIAL // Seth K. Bates // {datetime.now().year}"
        worksheet2.merge_cells(start_row=1, start_column=1, end_row=1, end_column=len(df.columns))
        cell = worksheet2.cell(row=1, column=1)
        cell.value = banner_text
        cell.fill = PatternFill(start_color="FF0000", end_color="FF0000", fill_type="solid")
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.font = Font(bold=True, color="FFFFFF")
        for idx, col in enumerate(df.columns, 1):
            max_length = max(df[col].astype(str).map(len).max(), len(str(col))) + 2
            if col == "File":
                max_length = min(max_length, 50)
            elif col == "Match":
                max_length = max(max_length, 30)
            worksheet2.column_dimensions[get_column_letter(idx)].width = max_length
            for row in range(3, 3 + len(df)):
                alignment = Alignment(horizontal="left") if col == "Line" else Alignment(horizontal="general")
                worksheet2.cell(row=row, column=idx).alignment = alignment
        last_col_letter = get_column_letter(len(df.columns))
        worksheet2.auto_filter.ref = f"A2:{last_col_letter}2"
        worksheet2.freeze_panes = worksheet2["A2"]
        # Insert Findings chart image
        if findings_img and os.path.exists(findings_img):
            img2 = ExcelImage(findings_img)
            img2.anchor = f"A{len(df)+4}"
            worksheet2.add_image(img2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a directory for sensitive data and code statistics.")
    parser.add_argument('-d', '--directory', required=True, help='Directory to scan')
    parser.add_argument('-o', '--output', required=True, help='Output Excel file name (e.g., results.xlsx)')
    args = parser.parse_args()
    output_file = args.output
    if not output_file.endswith('.xlsx'):
        output_file += '.xlsx'
    print(f"Scanning directory {args.directory}...")
    results = scan_directory(args.directory)
    print("Counting lines of code by language...")
    loc_df = count_lines_per_language(args.directory)
    with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as loc_img:
        loc_img_path = loc_img.name
    if loc_df is not None and not loc_df.empty:
        plot_loc_chart(loc_df, loc_img_path)
    else:
        loc_img_path = None
    with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as findings_img:
        findings_img_path = findings_img.name
    if results:
        plot_findings_chart(results, findings_img_path)
    else:
        findings_img_path = None
    print(f"Saving results to {output_file}...")
    save_to_excel(results, output_file, loc_df=loc_df, loc_img=loc_img_path, findings_img=findings_img_path)
    print("Scan complete and results saved!")