#!/usr/bin/env python3
"""
PDF-XSS Payload Testing Framework v2.0 - Simplified
====================================================

Simplified testing framework for PDF XSS payloads with basic validation
and effectiveness scoring.

Features:
- Payload syntax validation
- Browser compatibility checking
- Basic effectiveness testing
- Simplified reporting

Author: SNGWN
Version: 2.0
"""

import json
import os
import sys
import re
import hashlib
from datetime import datetime

def load_payloads_for_browser(browser):
    """Load payloads for a specific browser"""
    browser_file = f"{browser}.json"
    
    if not os.path.exists(browser_file):
        return []
    
    try:
        with open(browser_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('payloads', [])
    except Exception as e:
        print(f"Error loading {browser_file}: {e}")
        return []

def validate_payload_syntax(payload):
    """Basic JavaScript payload syntax validation"""
    if not payload or len(payload) < 5:
        return False, "Payload too short"
    
    # Check for basic JavaScript elements
    js_patterns = [
        r'function\s*\(',
        r'var\s+\w+',
        r'let\s+\w+',
        r'const\s+\w+',
        r'=\s*function',
        r'alert\s*\(',
        r'console\.',
        r'window\.',
        r'document\.',
        r'parent\.',
        r'app\.',
        r'=>',
        r'try\s*{',
        r'catch\s*\(',
        r'if\s*\(',
        r'for\s*\(',
        r'while\s*\('
    ]
    
    for pattern in js_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True, "Valid JavaScript syntax detected"
    
    return False, "No recognizable JavaScript patterns found"

def check_evasion_techniques(payload):
    """Check for evasion techniques in payload"""
    techniques = {
        'obfuscation': {
            'base64': r'atob\s*\(',
            'hex_encoding': r'\\x[0-9a-fA-F]{2}',
            'unicode': r'\\u[0-9a-fA-F]{4}',
            'string_concat': r'\+\s*["\']',
            'eval': r'eval\s*\(',
            'function_constructor': r'Function\s*\(',
        },
        'dom_access': {
            'parent_access': r'parent\.',
            'window_access': r'window\.',
            'document_access': r'document\.',
            'location_redirect': r'location\s*=',
        },
        'sandbox_escape': {
            'file_access': r'file://',
            'external_url': r'https?://',
            'app_methods': r'app\.',
            'form_submit': r'submit\s*\(',
        }
    }
    
    found_techniques = []
    for category, patterns in techniques.items():
        for technique, pattern in patterns.items():
            if re.search(pattern, payload, re.IGNORECASE):
                found_techniques.append(f"{category}:{technique}")
    
    return found_techniques

def test_payload_effectiveness(payload_data):
    """Test payload effectiveness and assign score"""
    payload = payload_data.get('payload', '')
    
    # Base score
    score = 50
    
    # Syntax validation
    is_valid, reason = validate_payload_syntax(payload)
    if not is_valid:
        score -= 30
    
    # Check for evasion techniques
    techniques = check_evasion_techniques(payload)
    score += len(techniques) * 5  # +5 points per technique
    
    # Risk level bonus
    risk_level = payload_data.get('risk_level', 'medium').lower()
    risk_bonus = {'low': 0, 'medium': 10, 'high': 20, 'critical': 30}
    score += risk_bonus.get(risk_level, 0)
    
    # Payload length (longer payloads are often more sophisticated)
    if len(payload) > 200:
        score += 10
    elif len(payload) > 500:
        score += 20
    
    # Browser-specific optimizations
    browser = payload_data.get('browser', '').lower()
    if browser == 'chrome' and 'PDFium' in payload:
        score += 15
    elif browser == 'firefox' and 'PDF.js' in payload:
        score += 15
    
    # Cap score at 100
    score = min(score, 100)
    
    return {
        'score': score,
        'valid_syntax': is_valid,
        'syntax_reason': reason,
        'evasion_techniques': techniques,
        'risk_level': risk_level
    }

def run_browser_tests(browser):
    """Run tests for a specific browser"""
    print(f"\n🧪 TESTING {browser.upper()} PAYLOADS")
    print("=" * 50)
    
    payloads = load_payloads_for_browser(browser)
    if not payloads:
        print(f"❌ No payloads found for {browser}")
        return
    
    results = []
    total_score = 0
    valid_count = 0
    
    for i, payload_data in enumerate(payloads, 1):
        result = test_payload_effectiveness(payload_data)
        results.append({
            'payload_id': payload_data.get('id', f'unknown_{i}'),
            'technique': payload_data.get('technique', 'unknown'),
            'category': payload_data.get('category', 'unknown'),
            **result
        })
        
        total_score += result['score']
        if result['valid_syntax']:
            valid_count += 1
        
        # Print individual result
        status = "✅" if result['valid_syntax'] else "❌"
        print(f"{status} {payload_data.get('id', f'payload_{i}'):<20} "
              f"Score: {result['score']:3d}/100 "
              f"Techniques: {len(result['evasion_techniques'])}")
    
    # Summary
    avg_score = total_score / len(payloads) if payloads else 0
    validity_rate = (valid_count / len(payloads)) * 100 if payloads else 0
    
    print(f"\n📊 BROWSER SUMMARY - {browser.upper()}")
    print("-" * 30)
    print(f"Total Payloads: {len(payloads)}")
    print(f"Valid Payloads: {valid_count} ({validity_rate:.1f}%)")
    print(f"Average Score: {avg_score:.1f}/100")
    
    # Top 5 payloads
    top_payloads = sorted(results, key=lambda x: x['score'], reverse=True)[:5]
    print(f"\n🏆 TOP 5 PAYLOADS:")
    for i, payload in enumerate(top_payloads, 1):
        print(f"{i}. {payload['payload_id']} - {payload['score']}/100")
    
    return results

def generate_test_report(all_results):
    """Generate comprehensive test report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"test_report_{timestamp}.json"
    
    report = {
        'metadata': {
            'timestamp': timestamp,
            'generator': 'PDF-XSS Payload Tester v2.0',
            'author': 'SNGWN'
        },
        'summary': {},
        'detailed_results': all_results
    }
    
    # Calculate overall statistics
    all_scores = []
    all_valid = 0
    all_total = 0
    
    for browser, results in all_results.items():
        browser_scores = [r['score'] for r in results]
        browser_valid = sum(1 for r in results if r['valid_syntax'])
        
        all_scores.extend(browser_scores)
        all_valid += browser_valid
        all_total += len(results)
        
        report['summary'][browser] = {
            'total_payloads': len(results),
            'valid_payloads': browser_valid,
            'validity_rate': (browser_valid / len(results)) * 100 if results else 0,
            'average_score': sum(browser_scores) / len(browser_scores) if browser_scores else 0,
            'max_score': max(browser_scores) if browser_scores else 0,
            'min_score': min(browser_scores) if browser_scores else 0
        }
    
    report['summary']['overall'] = {
        'total_payloads': all_total,
        'valid_payloads': all_valid,
        'validity_rate': (all_valid / all_total) * 100 if all_total else 0,
        'average_score': sum(all_scores) / len(all_scores) if all_scores else 0
    }
    
    # Save report
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n📄 Test report saved: {report_file}")
    return report_file

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="PDF-XSS Payload Testing Framework v2.0")
    parser.add_argument('-b', '--browser', 
                        choices=['chrome', 'firefox', 'safari', 'adobe', 'edge', 'all'],
                        default='all',
                        help='Target browser to test (default: all)')
    parser.add_argument('--report', action='store_true',
                        help='Generate detailed JSON report')
    
    args = parser.parse_args()
    
    print("🧪 PDF-XSS PAYLOAD TESTING FRAMEWORK v2.0")
    print("=" * 50)
    
    all_results = {}
    
    if args.browser == 'all':
        browsers = ['chrome', 'firefox', 'safari', 'adobe', 'edge']
    else:
        browsers = [args.browser]
    
    for browser in browsers:
        results = run_browser_tests(browser)
        if results:
            all_results[browser] = results
    
    if args.report and all_results:
        generate_test_report(all_results)
    
    print(f"\n✅ Testing complete for {len(all_results)} browser(s)")

if __name__ == "__main__":
    main()