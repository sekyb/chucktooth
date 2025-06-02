![ChuckTooth Logo](chucktooth.webp)

# ChuckTooth.py

`chucktooth` is a Python script that scans a specified directory for files containing potentially sensitive information. It detects patterns such as IP addresses, emails, passwords, API keys, secrets, credit card numbers, and more. The results are output to a detailed Excel report, including summary charts.

---

## Features

- **Recursive Directory Scan**: Scans all supported files in a directory and its subdirectories.
- **Sensitive Data Detection**: Identifies a wide variety of sensitive information:
  - IPv4 and IPv6 addresses
  - Email addresses
  - Passwords, API keys, and generic tokens
  - Credit card numbers
  - AWS keys, MongoDB URIs, Docker credentials, and more
- **Multi-language Support**: Handles a range of source and config file types (see below).
- **Comprehensive Report**: Outputs results as a multi-tab Excel file with:
  - An executive summary
  - A detailed results tab (with file, line number, pattern type, and matched value)
  - Charts visualizing findings and code statistics
- **Progress Bar**: Real-time progress bar for scanning.
- **Verbose Logging**: All scan details and findings are logged to a `Logjam` file for later review.

---

## Requirements

- Python 3.x
- [pandas](https://pandas.pydata.org/)
- [openpyxl](https://openpyxl.readthedocs.io/en/stable/)
- [matplotlib](https://matplotlib.org/)
- [tqdm](https://tqdm.github.io/)

Install the required libraries with:

```bash
pip install -r requirements.txt
```

---

## How to Use

1. **Clone or download** the `chucktooth.py` script.
2. Run the script from the terminal, specifying the directory to scan and (optionally) the output Excel file:

    ```bash
    python chucktooth.py -d /path/to/your/project -o results.xlsx
    ```

    - `-d` or `--directory`: Directory to scan (*required*)
    - `-o` or `--output`: Name of Excel output file (default: `results.xlsx`)

3. **Monitor the progress bar** in your terminal as the scan proceeds.
4. When complete, open the generated Excel report for results and charts.
5. For full scan details, refer to the `Logjam` file created in the same directory.

---

### Example Usage

```bash
python chucktooth.py -d ~/projects/myrepo -o scan_report.xlsx

Scanning directory ~/projects/myrepo...
Counting lines of code by language...
Saving results to scan_report.xlsx...
Scan complete and results saved!
```

---

### Supported File Types

By default, the script scans files with the following extensions:

- `.txt`, `.py`, `.js`, `.html`, `.json`, `.env`, `.yml`, `.yaml`, `.ini`, `.cfg`, and any file containing a dot in its name

You can modify or extend the supported file types in the script by editing the file extension list.

---

## Output

- **Excel File**: Multi-sheet report with banners, summary charts, and detailed findings (file, line, pattern, match).
- **Logjam File**: All scan details and matches are written to `Logjam` for auditing and troubleshooting.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.