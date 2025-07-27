# Excel-XSS Tool v3.0 - Advanced Excel Browser Exploitation

## 🚀 Excel Browser Rendering XSS Framework

A research-grade tool for generating Excel files with sophisticated payloads designed to exploit Excel files when rendered in web browsers. Features 60+ distinct payloads targeting Chrome Excel rendering, Firefox Excel handling, Safari Excel integration, Edge Excel processing, Office 365 Web Excel, and Google Sheets Excel import functionality.

## 📁 Project Structure

```
Excel-XSS/
├── export_to_excel.py           # Main Excel browser payload exporter
├── excel_payloads.json         # Consolidated Excel payload database
├── merge_json_payloads.py      # JSON payload database merger utility
├── requirements.txt            # Python dependencies
└── README.md                   # This file
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

## 🛠️ Installation & Requirements

### Requirements
- Python 3.x
- pandas
- openpyxl

### Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Export Excel browser payload database to Excel format
python3 export_to_excel.py
```

## 📊 Excel Browser Payload Export

### Overview
The Excel browser payload export provides comprehensive security research data focused on Excel files rendered in web browsers, targeting legacy Excel formats with reduced security restrictions.

### Features
- **Excel Browser Focus**: Payloads targeting Excel files opened in web browsers
- **Legacy Format Targeting**: Emphasis on older Excel standards (.xls) with lower security restrictions
- **Comprehensive Research**: GitHub, CVE database, security conferences analysis
- **Multiple Analysis Sheets**: Browser-specific, Excel format analysis, CVE references, research summary
- **Professional Formatting**: Tables, conditional formatting, and organized layouts for security research

### Usage
```bash
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

# View available payloads in JSON format
cat excel_payloads.json | jq '.metadata'

# Extract payloads by browser
cat excel_payloads.json | jq '.payloads[] | select(.browser=="chrome")'

# Count payloads by category
cat excel_payloads.json | jq '.payloads | group_by(.category) | map({category: .[0].category, count: length})'
```

## 🎯 Excel File Format Targets

| Format | Description | Payload Count | Focus Areas |
|--------|-------------|---------------|-------------|
| .xls | Legacy Excel 97-2003 | 15+ | Reduced security restrictions, ActiveX support |
| .xlsx | Modern Excel XML | 20+ | XXE exploitation, XML structure abuse |
| .xlsm | Macro-enabled Excel | 15+ | VBA macro execution in browser context |
| .xlsb | Binary Excel | 10+ | Performance optimized, detection evasion |

## 📊 Browser Compatibility

| Browser | Excel Viewer | Payload Count | Key Techniques |
|---------|-------------|---------------|----------------|
| Chrome | Google Drive, Chromium | 12+ | DOM manipulation, drive integration |
| Firefox | Plugin-based rendering | 10+ | Gecko engine exploitation |
| Safari | macOS Excel integration | 8+ | WebKit engine abuse |
| Edge | Windows Excel integration | 10+ | ActiveX legacy, WebView2 |
| Office 365 Web | Browser Excel app | 15+ | SharePoint integration abuse |
| Google Sheets | Excel import processing | 5+ | File conversion vulnerabilities |

## 🔍 Excel Security Testing Methodology

1. **Generate Excel Test Files**: Use the tool to create Excel files with various browser exploitation payloads
2. **Upload/Share Testing**: Test file upload functionality and sharing mechanisms
3. **Browser Excel Viewer Analysis**: Test different browser Excel viewers and online services
4. **Formula Injection Testing**: Test malicious formula execution in browser context
5. **Data Exfiltration Testing**: Test external data connection abuse
6. **Cross-Browser Testing**: Verify payload effectiveness across different browsers

## 🛡️ Excel-Specific Defensive Measures

To protect against Excel browser exploitation attacks:

- **Disable External Data Connections**: Block HTTP/UNC path connections from Excel files
- **Formula Execution Restrictions**: Disable or restrict formula execution in browser Excel viewers
- **Macro Security**: Implement strict macro execution policies for browser-rendered Excel files
- **File Upload Validation**: Scan uploaded Excel files for suspicious formulas and external connections
- **Content Security Policy**: Implement CSP headers that restrict Excel-initiated requests
- **User Education**: Train users on Excel security risks when opening files in browsers

## 📈 Changelog

### Version 3.0 (Current) - Excel Browser Rendering Focus
- **60+ Excel browser exploitation payloads**
- **Legacy format emphasis**: Targeting .xls files with reduced security restrictions
- **Cross-browser compatibility**: Chrome, Firefox, Safari, Edge, Office 365, Google Sheets
- **Advanced research base**: 100+ CVE references, security conferences, GitHub research
- **Professional Excel export**: Multi-sheet analysis with comprehensive research documentation
- **CVE reference integration**: Each payload linked to relevant Excel security vulnerabilities

## 🚨 Security Considerations

- Always obtain proper authorization before testing
- Use in controlled environments only
- Be aware of legal implications
- Respect responsible disclosure practices
- Monitor and log all testing activities

## 🔗 Resources

- [OWASP Testing Guide - File Upload Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [Microsoft Excel Security](https://docs.microsoft.com/en-us/deployoffice/security/)
- [Excel Formula Injection](https://owasp.org/www-community/attacks/CSV_Injection)

## 📄 License

This project is for educational and authorized security testing purposes only. Please use responsibly and in accordance with applicable laws and regulations.