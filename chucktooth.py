import os
import re
import pandas as pd
from openpyxl.utils import get_column_letter
from openpyxl.styles import PatternFill, Alignment, Font
from datetime import datetime
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
import argparse

# Regular expressions for detecting sensitive information
patterns = {
    "IP Address (IPv4)": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "IP Address (IPv6)": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Password": r"(?i)(password|secret|pass|passwd|api_key|token|apikey|access_token|client_secret|client_id)[\s=:\"']{0,5}([A-Za-z0-9!@#$%^&*()_+={}\[\]|;:<>,.?/~`-]{8,})",
    "URL": r"\b(?:https?|ftp|file)://[^\s\"'>]+",
    "Base64 Encoded": r"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b",
    "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
    "AWS Secret Key": r"\b(?:ASIA|AKIA)[A-Za-z0-9/+=]{32,40}\b",
    "Private Key (RSA)": r"-----BEGIN (RSA )?PRIVATE KEY-----[\s\S]+?-----END (RSA )?PRIVATE KEY-----",
    "MongoDB URI": r"\bmongodb(?:\+srv)?:\/\/[^\s\"'>]+",
    "Docker Credentials": r"//([A-Za-z0-9._-]+:[A-Za-z0-9!@#$%^&*()_+={}|;:<>,.?/~`-]+)@",
    "Generic Token": r"\b[a-zA-Z0-9-_]{32,64}\b"
}

def scan_file(file_path):
    results = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f, start=1):
                for key, pattern in patterns.items():
                    for match in re.findall(pattern, line):
                        match_text = match[0] if isinstance(match, tuple) else match
                        results.append({
                            'File': file_path,
                            'Line': i,
                            'Pattern': key,
                            'Match': match_text
                        })
    except Exception as e:
        pass
    return results

def scan_directory(directory):
    all_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.txt', '.py', '.js', '.html', '.json')) or '.' in file:
                all_files.append(os.path.join(root, file))

    results = []
    with ThreadPoolExecutor() as executor:
        for file_results in tqdm(executor.map(scan_file, all_files), total=len(all_files), desc="Scanning files"):
            results.extend(file_results)

    return results

def save_to_excel(results, output_file):
    df = pd.DataFrame(results)

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
                max_length = min(max_length, 50)  # Cap File column width
            elif col == "Match":
                max_length = max(max_length, 30)  # Ensure Match column isn't squashed
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