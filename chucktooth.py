import os
import re
import pandas as pd
from openpyxl.utils import get_column_letter

# Regular expressions for detecting sensitive information
patterns = {
    # IP Addresses (IPv4 and IPv6)
    "IP Address (IPv4)": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "IP Address (IPv6)": r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",

    # Email Addresses
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",

    # Refined Password Pattern to catch only more specific cases
    "Password": r"(password|secret|pass|passwd|api_key|token|apikey|access_token|client_secret|client_id|password123|key)[\s=:]*['\"]?([A-Za-z0-9!@#$%^&*()_+={}|;:<>,.?/~`-]{8,})['\"]?",

    # URLs and URLs with potential sensitive information
    "URL": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+|ftp://(?:[-\w.]|(?:%[\da-fA-F]{2}))+|file://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",

    # Refined Base64 Encoded (matches likely secrets or tokens)
    "Base64 Encoded": r"([A-Za-z0-9+/=]{32,64})",

    # Credit card numbers (e.g., Visa, MasterCard, etc.)
    "Credit Card": r"4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(2014|2149)[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}",

    # AWS and other cloud keys (e.g., AWS keys)
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"secret_key=[A-Za-z0-9/+=]{40}",

    # Private RSA/SSH keys
    "Private Key (RSA)": r"-----BEGIN (RSA )?PRIVATE KEY-----([A-Za-z0-9+/=]+\n)+-----END (RSA )?PRIVATE KEY-----",

    # MongoDB URI
    "MongoDB URI": r"mongodb(?:\+srv)?://(?:\w+:\w+@)?[A-Za-z0-9.-]+(?:/\w+)?",

    # Docker credentials (username:password)
    "Docker Credentials": r"(?<=//)[A-Za-z0-9_-]+:[A-Za-z0-9!@#$%^&*()_+={}|;:<>,.?/~`-]+(?=@)",

    # Generic keys and tokens
    "Generic Token": r"[A-Za-z0-9-_]{32,64}",
}

# Function to scan files in the directory
def scan_directory(directory):
    results = []
    
    # Loop through all files in the directory
    print(f"Scanning directory: {directory}")  # Debugging line
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Checking file: {file_path}")  # Debugging line
            if file.endswith(('.txt', '.py', '.js', '.html', '.json', '.*')):  # Add file types as needed
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                        # Scan for patterns and store the results
                        for key, pattern in patterns.items():
                            print(f"Scanning for {key}...")  # Debugging line
                            matches = re.findall(pattern, content)
                            if matches:
                                print(f"Found matches for {key}: {matches}")  # Debugging line
                                for match in matches:
                                    results.append({
                                        'File': file_path,
                                        'Pattern': key,
                                        'Match': match
                                    })
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")
    return results

# Function to compile results into an Excel spreadsheet with auto‐adjusted column widths
def save_to_excel(results, output_file):
    df = pd.DataFrame(results)
    
    # Use openpyxl engine explicitly
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Results')
        worksheet = writer.sheets['Results']
        
        # Auto‐adjust column widths
        for idx, col in enumerate(df.columns, 1):
            # Find the maximum length in this column (including header)
            max_length = max(
                df[col].astype(str).map(len).max(),
                len(str(col))
            ) + 2  # add a little extra padding
            column_letter = get_column_letter(idx)
            worksheet.column_dimensions[column_letter].width = max_length

# Main execution
if __name__ == "__main__":
    directory = input("Enter the directory to scan: ")
    output_file = input("Enter the output Excel file name (e.g., results.xlsx): ")

    # Ensure the file ends with .xlsx
    if not output_file.endswith('.xlsx'):
        output_file += '.xlsx'

    print(f"Scanning directory {directory}...")
    results = scan_directory(directory)

    if results:
        print(f"Found {len(results)} potential issues. Saving to {output_file}...")
        save_to_excel(results, output_file)
        print("Scan complete and results saved!")
    else:
        print("No sensitive data found.")
