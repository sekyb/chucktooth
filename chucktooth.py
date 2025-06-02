import os
import re
import pandas as pd
from openpyxl.utils import get_column_letter
from openpyxl.styles import PatternFill, Alignment, Font
from datetime import datetime
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
import argparse

# Placeholders to filter out obvious false positives
PLACEHOLDER_VALUES = {
    "password", "token", "secret", "string", "null", "none", "default", "example", "changeme"
}

def is_potential_secret(s):
    if not isinstance(s, str):
        return False
    s_lower = s.lower()
    if s_lower in PLACEHOLDER_VALUES:
        return False
    if len(set(s)) <= 3:
        return False  # Too repetitive
    if s.isdigit() or s.islower() or s.isupper():
        return False
    if len(s) < 8:
        return False
    return True

# Improved and specific regex patterns for sensitive information
patterns = {
    # IPv4: Only matches valid 0-255 octets
    "IP Address (IPv4)": r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b",
    # IPv6: Matches full and compressed forms (practical coverage, not exhaustive)
    "IP Address (IPv6)": r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b|\b::(?:[A-Fa-f0-9]{1,4}:){0,5}[A-Fa-f0-9]{1,4}\b",
    # Email
    "Email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,7}\b",
    # Passwords, API Keys, Tokens, Secrets, etc.
    "Password/Token/Secret": r"""(?ix)
        \b(password|secret|pass(word)?|passwd|api_?key|token|access_token|client_secret|client_id)\b
        \s* (?:=|:)\s* 
        ['"]
        (?P<secret>[A-Za-z0-9!@#$%^&*()_+={}\[\]|;:<>,.?/~`-]{8,})
        ['"]
    """,
    # URLs (http, https, ftp, file)
    "URL": r"\b(?:https?|ftp|file)://[^\s\"'><)]+",
    # Base64: At least 40 chars, optional padding, word boundary
    "Base64 Encoded": r"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b",
    # Credit Card Numbers: Visa, MC, Amex, Discover; word boundaries
    "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    # AWS Access Key: Always starts with AKIA, 16 uppercase letters/digits
    "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
    # AWS Secret Key: Typically 40 chars
    "AWS Secret Key": r"\b(?:ASIA|AKIA)[A-Za-z0-9/+=]{16,40}\b",
    # Private Keys: RSA, EC, DSA; multiline, non-greedy
    "Private Key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----[\s\S]+?-----END (RSA |EC |DSA )?PRIVATE KEY-----",
    # MongoDB URI: Matches both standard and +srv
    "MongoDB URI": r"\bmongodb(?:\+srv)?:\/\/[^\s\"'<>]+",
    # Docker Credentials: Looks for //username:password@, password must be at least 8 chars
    "Docker Credentials": r"//([A-Za-z0-9._-]+:[A-Za-z0-9!@#$%^&*()_+={}|;:<>,.?/~`-]{8,})@",
    # Generic Token: 32-64 chars, at least one digit and one letter, word boundaries
    "Generic Token": r"\b(?=[a-zA-Z0-9-_]{32,64}\b)(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z0-9-_]{32,64}\b"
}

# Patterns that require re.VERBOSE and/or re.IGNORECASE
pattern_flags = {
    "Password/Token/Secret": re.IGNORECASE | re.VERBOSE,
    "Private Key": re.DOTALL
}

def remove_illegal_excel_chars(val):
    if isinstance(val, str):
        # Remove ASCII control characters except for \t (tab) and \n (newline)
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
                            # Only include if password part is not a placeholder
                            if not is_potential_secret(match_text.split(':', 1)[-1]):
                                continue
                        elif key == "Private Key":
                            # Usually multiline, handled below
                            continue
                        else:
                            match_text = match.group(0)
                        results.append({
                            'File': file_path,
                            'Line': i,
                            'Pattern': key,
                            'Match': match_text
                        })
        # Special handling for Private Key blocks (multiline)
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
                    'Match': match_text[:60] + ('...' if len(match_text) > 60 else '')  # Preview only
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

def save_to_excel(results, output_file):
    df = pd.DataFrame(results)

    # Remove illegal Excel characters from all string values
    for col in df.columns:
        df[col] = df[col].map(remove_illegal_excel_chars)

    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Results', startrow=1)

        workbook = writer.book
        worksheet = writer.sheets['Results']

        banner_text = f"CONFIDENTIAL // Seth K. Bates // {datetime.now().year}"
        worksheet.merge_cells(start_row=1, start_column=1, end_row=1, end_column=len(df.columns))
        cell = worksheet.cell(row=1, column=1)
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
            worksheet.column_dimensions[get_column_letter(idx)].width = max_length

            for row in range(3, 3 + len(df)):
                alignment = Alignment(horizontal="left") if col == "Line" else Alignment(horizontal="general")
                worksheet.cell(row=row, column=idx).alignment = alignment

        last_col_letter = get_column_letter(len(df.columns))
        worksheet.auto_filter.ref = f"A2:{last_col_letter}2"
        worksheet.freeze_panes = worksheet["A2"]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a directory for sensitive data.")
    parser.add_argument('-d', '--directory', required=True, help='Directory to scan')
    parser.add_argument('-o', '--output', required=True, help='Output Excel file name (e.g., results.xlsx)')
    args = parser.parse_args()

    output_file = args.output
    if not output_file.endswith('.xlsx'):
        output_file += '.xlsx'

    print(f"Scanning directory {args.directory}...")
    results = scan_directory(args.directory)

    if results:
        print(f"Found {len(results)} potential issues. Saving to {output_file}...")
        save_to_excel(results, output_file)
        print("Scan complete and results saved!")
    else:
        print("No sensitive data found.")