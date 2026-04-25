# Excel-XSS Exporter v2.0

Professional Excel browser rendering payload database exporter for authorized security testing.

## Overview

Excel-XSS Exporter is a research tool that exports a comprehensive database of Excel browser rendering exploitation payloads to professional Excel format (.xlsx). This tool is designed for security researchers, penetration testers, and red team operations to analyze and test Excel-based attack vectors in web browser environments.

**Legal Notice**: This tool is for authorized security testing and educational purposes only. Ensure you have explicit permission before testing any systems.

## Features

- ✅ **60+ Payloads**: Research-backed Excel browser rendering exploits
- ✅ **Multi-Format Support**: .xls, .xlsx, .xlsm, .xlsb format exploitation
- ✅ **Browser Compatibility**: Chrome, Firefox, Safari, Edge, Office 365 Web, Google Sheets
- ✅ **Professional Excel Output**: Multi-sheet workbooks with comprehensive documentation
- ✅ **Advanced Payloads**: Formula injection, macro execution, XXE exploitation, CSV injection
- ✅ **Production Logging**: Structured logging with configurable levels
- ✅ **Research-Based**: Built on 100+ CVE references and security conference research
- ✅ **No Complex Dependencies**: Uses pandas and openpyxl only

## Quick Start

### Prerequisites
- Python 3.7+
- Required packages: pandas, openpyxl

### Installation

```bash
cd Excel-XSS
pip install -r requirements.txt
```

### Basic Usage

```bash
# Export payloads to Excel with default settings
python3 export_to_excel.py

# Export with debug logging
python3 export_to_excel.py --log-level DEBUG

# Export to custom output directory
python3 export_to_excel.py --output-dir /path/to/output

# Save logs to file
python3 export_to_excel.py --log-file export.log
```

## Command Line Reference

### Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `--log-level` | Logging level (DEBUG, INFO, WARNING, ERROR) | INFO |
| `--log-file` | Path to log file (optional) | Console only |
| `-o, --output-dir` | Output directory for Excel file | `output` |
| `--help` | Show help message | - |

### Log Levels

- **DEBUG**: Detailed payload information and processing steps
- **INFO**: Status updates and summary information (default)
- **WARNING**: Important notices and security warnings
- **ERROR**: Failures and error conditions

## Payload Categories

### Formula Injection
Malicious Excel formulas executed in browser context:
- `=cmd|'/c calc'!A1`
- `=cmd|'/c powershell.exe'!A1`
- `@SUM(1+9)*cmd|'/c whoami'!A1`

### Macro Execution
VBA macro payloads for browser-rendered Excel files:
- AutoOpen trigger macros
- Document_Open event handlers
- DLL injection techniques

### External Data Connections
HTTP/UNC path abuse for data exfiltration:
- External data connections to attacker servers
- UNC path traversal
- HTTP request interception

### XML External Entity (XXE)
Excel XML format exploitation:
- External entity definitions in XLSX structure
- DTD injection in Excel XML
- Entity expansion attacks

### CSV Injection
CSV-based formula injection in browser Excel viewers:
- Formula injection via CSV import
- Cross-sheet formula references
- Hidden formula execution

### Browser DOM Access
Excel-to-browser DOM manipulation techniques:
- XSS via Excel to browser bridge
- DOM injection payloads
- Cross-window communication

## Generated Output

The tool exports payloads to a professional Excel workbook with the following sheets:

1. **All Payloads**: Complete payload list with details
2. **By Browser**: Payloads organized by target browser
3. **By Category**: Payloads grouped by attack technique
4. **By Risk Level**: Payloads sorted by severity
5. **Statistics**: Summary analysis and metrics
6. **Documentation**: Research references and CVE citations

### Output Naming

```
excel_payloads_YYYYMMDD_HHMMSS.xlsx
```

Example: `excel_payloads_20260426_143022.xlsx`

## Security Testing Methodology

### 1. Preparation
- Identify target Excel application (Office 365, Google Sheets, etc.)
- Set up monitoring for payload execution
- Prepare test environment in isolated network

### 2. Payload Selection
- Export payloads from Excel-XSS Exporter
- Select payloads by browser/category from exported Excel
- Customize payloads for target environment

### 3. Delivery & Testing
- Upload/import Excel file to target application
- Monitor for formula execution or macro triggers
- Test across different Excel versions
- Document successful techniques

### 4. Analysis
- Review generated workbook for detailed payload info
- Cross-reference payloads with CVE database
- Document browser-specific vulnerabilities
- Report findings responsibly

## Logging Output

The tool provides structured logging with timestamps:

```
2026-04-26 02:15:33,192 - INFO - Excel Browser Rendering Payload Exporter v2.0
2026-04-26 02:15:33,192 - INFO - Output directory: output
2026-04-26 02:15:33,193 - INFO - Searching for Excel browser payload database
2026-04-26 02:15:33,193 - INFO - Found excel_payloads.json
2026-04-26 02:15:33,194 - INFO - Loaded 60 Excel browser payloads
2026-04-26 02:15:33,195 - INFO - Creating Excel workbook with payload data...
2026-04-26 02:15:33,245 - INFO - Excel export complete - output/excel_payloads_20260426_021533.xlsx
2026-04-26 02:15:33,245 - WARNING - These payloads are for authorized security testing only
```

## Payload Database Structure

The `excel_payloads.json` file contains payload data with this structure:

```json
{
  "browser": "chrome",
  "payloads": [
    {
      "id": "excel_formula_001",
      "category": "formula_injection",
      "technique": "cmd_execution_2024",
      "payload": "=cmd|'/c calc'!A1",
      "description": "Execute calculator via formula injection",
      "risk_level": "high",
      "cve_reference": "CVE-2024-XXXXX",
      "target_formats": [".xls", ".xlsx", ".xlsm"]
    },
    ...
  ],
  "metadata": {
    "focus": "Excel browser rendering",
    "target_formats": [".xls", ".xlsx", ".xlsm", ".xlsb"],
    "browser_targets": ["Chrome", "Firefox", "Safari", "Edge", "Office 365", "Google Sheets"]
  }
}
```

## Best Practices

### For Security Researchers
1. ✅ Use debug logging (`--log-level DEBUG`) for detailed analysis
2. ✅ Test payloads in isolated environments only
3. ✅ Document which payloads work on each platform/version
4. ✅ Share findings through responsible disclosure
5. ✅ Keep logs for security audit trails

### For Red Team Operations
1. ✅ Export payloads to custom directory with meaningful naming
2. ✅ Organize by browser/category for targeted campaigns
3. ✅ Use logging for operational security (OSInt mitigation)
4. ✅ Archive generated workbooks for post-assessment reporting
5. ✅ Customize payloads for specific target environments

### For Blue Team Defense
1. ✅ Understand Excel formula injection vectors
2. ✅ Implement strict Excel upload validation
3. ✅ Disable external data connections
4. ✅ Monitor for suspicious formula patterns
5. ✅ Restrict Excel file extensions

## Defensive Measures

### Excel File Security
- **Disable Formulas**: Configure Excel to disable formula execution
- **Upload Validation**: Scan for suspicious formulas before processing
- **External Connections**: Block HTTP/UNC paths in Excel files
- **Macro Security**: Implement strict macro execution policies
- **Format Restrictions**: Allow only safe Excel formats

### Application Controls
- **File Upload Restrictions**: Whitelist safe file types
- **Content Validation**: Analyze file content, not just extension
- **User Education**: Train users on Excel security risks
- **Version Control**: Keep Excel and Office applications updated
- **Sandboxing**: Open Excel files in isolated environments

## Troubleshooting

### "No Excel browser payload database found"
**Solution**: Ensure `excel_payloads.json` exists in the same directory
```bash
ls -la excel_payloads.json  # Verify file exists
```

### Import errors (pandas, openpyxl)
**Solution**: Install required dependencies
```bash
pip install -r requirements.txt
```

### Permission denied on output directory
**Solution**: Create output directory with write permissions
```bash
mkdir -p output
chmod 755 output
```

### Logging not showing expected level
**Solution**: Verify --log-level argument
```bash
python3 export_to_excel.py --log-level DEBUG  # Enable debug logging
```

## File Structure

```
Excel-XSS/
├── export_to_excel.py      (single executable, v2.0)
├── excel_payloads.json     (60+ payload database)
├── requirements.txt        (dependencies: pandas, openpyxl)
├── README.md               (this file)
└── output/                 (generated Excel files directory)
```

## Requirements

```
pandas>=1.0.0
openpyxl>=3.0.0
```

## Research Foundation

This tool is built on extensive security research:

### Excel Security Research
- **100+ CVE References**: Excel formula injection, macro execution, XXE vulnerabilities
- **Security Conferences**: BlackHat, DEF CON, BSides presentations
- **Bug Bounty Programs**: HackerOne, Bugcrowd, Synack disclosures
- **Academic Papers**: Excel security analysis and exploitation techniques

### Key References
- OWASP Testing Guide - File Upload Testing
- Microsoft Excel Security Documentation
- Excel Formula Injection Research Papers
- CSV Injection Attack Documentation

## Version History

- **v2.0** (Current): Consolidated architecture, production logging, enhanced error handling
- **v1.0**: Initial release, basic Excel export functionality

## Contributing

For improvements or additional payloads:

1. Ensure payloads are thoroughly tested
2. Include CVE references and research citations
3. Follow existing JSON structure
4. Test across multiple Excel versions
5. Document any new attack techniques

## Security Notice

⚠️ **WARNING**: These payloads are designed to exploit Excel browser rendering vulnerabilities. Use only for:
- Authorized security testing
- Authorized penetration testing
- Approved red team operations
- Educational purposes in controlled environments

Unauthorized access to computer systems is **illegal** and may violate applicable laws.

## License

Educational and Authorized Security Testing Only

---

**Ready to Export**: Use `python3 export_to_excel.py` to begin analyzing Excel browser rendering vulnerabilities.

*Last Updated: 2026-04-26*
