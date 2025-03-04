![ChuckTooth Logo](chucktooth.webp)

# chucktooth Script

`chucktooth` is a Python script designed to scan a specified directory for files containing potentially sensitive information such as IP addresses, email addresses, passwords, API keys, credit card numbers, and more. The script uses regular expressions to identify sensitive data patterns in various file types and outputs the results in an Excel file.

## Features

- Scans files in a specified directory for sensitive information.
- Identifies various types of sensitive data, including but not limited to:
  - IP addresses (IPv4 & IPv6)
  - Email addresses
  - Passwords and API tokens
  - Credit card numbers
  - AWS keys, MongoDB URIs, Docker credentials, and more
- Outputs the results into an Excel file (`.xlsx` format).

## Requirements

- Python 3.x
- `pandas` library
- `openpyxl` library (for saving results to Excel)

You can install the required libraries using pip:

```bash
pip install pandas openpyxl
```

## How to Use

1. Clone or download the `chucktooth` script.
2. Place the script in a directory of your choice.
3. Run the script using Python:

    ```bash
    python chucktooth.py
    ```

4. When prompted, enter the directory you want to scan (e.g., `/path/to/your/project`).
5. Enter the output Excel file name (e.g., `results.xlsx`).

The script will scan files in the specified directory and output the results in an Excel file, where each match is listed with:
- File name
- Detected pattern (e.g., IP address, password)
- The matched value

### Supported File Types
- `.txt`
- `.py`
- `.js`
- `.html`
- `.json`

You can modify the supported file types in the script to add or remove file extensions.

## Example

```bash
Enter the directory to scan: /home/user/project
Enter the output Excel file name (e.g., results.xlsx): sensitive_data.xlsx
Scanning directory /home/user/project...
Found 10 potential issues. Saving to sensitive_data.xlsx...
Scan complete and results saved!
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
