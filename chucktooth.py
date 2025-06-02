import os
import re
import argparse
import pandas as pd
from openpyxl.utils import get_column_letter
from openpyxl.styles import PatternFill, Alignment, Font
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import json

# Regular expressions for detecting sensitive information
patterns = {
    "IP Address (IPv4)": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "IP Address (IPv6)": r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Password": r"(password|secret|pass|passwd|api_key|token|apikey|access_token|client_secret|client_id|password123|key)[\s=:]*['\"]?([A-Za-z0-9!@#$%^&*()_+={}|;:<>,.?/~`-]{8,})['\"]?",
    "URL": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+|ftp://(?:[-\w.]|(?:%[\da-fA-F]{2}))+|file://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",
    "Base64 Encoded": r"([A-Za-z0-9+/=]{32,64})",
    "Credit Card": r"4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(2014|2149)[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"secret_key=[A-Za-z0-9/+=]{40}",
    "Private Key (RSA)": r"-----BEGIN (RSA )?PRIVATE KEY-----([A-Za-z0-9+/=]+\n)+-----END (RSA )?PRIVATE KEY-----",
    "MongoDB URI": r"mongodb(?:\+srv)?://(?:\w+:\w+@)?[A-Za-z0-9.-]+(?:/\w+)?",
    "Docker Credentials": r"(?<=//)[A-Za-z0-9_-]+:[A-Za-z0-9!@#$%^&*()_+={}|;:<>,.?/~`-]+(?=@)",
    "Generic Token": r"[A-Za-z0-9-_]{32,64}",
}

# File extensions to scan
allowed_extensions = {".txt", ".py", ".js", ".html", ".json"}

# Scan a single file
def scan_file(file_path):
    matches = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            for key, pattern in patterns.items():
                found = re.findall(pattern, content)
                if found:
                    for match in found:
                        matches.append({
                            'File': file_path,
                            'Pattern': key,
                            'Match': match if isinstance(match, str) else match[0]
                        })
    except Exception:
        pass
    return matches

# Scan the directory with multithreading and progress bar
def scan_directory(directory):
    results = []
    files_to_scan = []

    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            if any(full_path.endswith(ext) for ext in allowed_extensions):
                files_to_scan.append(full_path)

    with ThreadPoolExecutor() as executor:
        future_to_file = {executor.submit(scan_file, file): file for file in files_to_scan}
        for future in tqdm(as_completed(future_to_file), total=len(future_to_file), desc="Scanning files"):
            results.extend(future.result())

    return results

# Save results to Excel
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
            col_letter = get_column_letter(idx)
            worksheet.column_dimensions[col_letter].width = max_length

        last_col_letter = get_column_letter(len(df.columns))
        worksheet.auto_filter.ref = f"A2:{last_col_letter}2"
        worksheet.freeze_panes = worksheet["A2"]

# Save results to JSON
def save_to_json(results, output_file):
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

# Main entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chucktooth: Scan directories for sensitive data.")
    parser.add_argument("-d", "--directory", required=True, help="Directory to scan")
    parser.add_argument("-o", "--output", required=True, help="Output file (with .xlsx or .json extension)")
    args = parser.parse_args()

    scan_results = scan_directory(args.directory)

    if scan_results:
        print(f"Found {len(scan_results)} potential issues.")
        if args.output.endswith(".xlsx"):
            save_to_excel(scan_results, args.output)
        elif args.output.endswith(".json"):
            save_to_json(scan_results, args.output)
        else:
            print("Unsupported output format. Use .xlsx or .json.")
    else:
        print("No sensitive data found.")
