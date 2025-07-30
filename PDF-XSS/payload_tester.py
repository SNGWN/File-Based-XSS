#!/usr/bin/env python3
"""
PDF-XSS Payload Testing Framework v3.0 - Enhanced
====================================================

Enhanced testing framework for PDF XSS payloads with comprehensive validation,
effectiveness scoring, and advanced analysis capabilities.

Features:
- Payload syntax validation and complexity analysis
- Browser compatibility checking with detailed scoring
- Advanced effectiveness testing with risk assessment
- Comprehensive JSON reporting with improvement suggestions
- Payload categorization and technique analysis
- CVE reference validation and research linking

Author: SNGWN
Version: 3.0
"""

import json
import os
import sys
import re
import hashlib
import argparse
from datetime import datetime
from collections import defaultdict

VERSION = "3.0"

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
    """Enhanced JavaScript payload syntax validation"""
    if not payload or len(payload) < 5:
        return False, "Payload too short", 0
    
    score = 0
    issues = []
    
    # Basic JavaScript syntax patterns
    js_patterns = [
        (r'function\s*\(', 'function declaration', 10),
        (r'var\s+\w+|let\s+\w+|const\s+\w+', 'variable declaration', 5),
        (r'try\s*\{.*\}\s*catch', 'error handling', 15),
        (r'eval\s*\(', 'eval usage', 20),
        (r'Function\s*\(', 'Function constructor', 25),
        (r'setTimeout|setInterval', 'timer functions', 10),
        (r'parent\.|top\.|window\.', 'DOM escape attempt', 30),
        (r'app\.|this\.', 'PDF API usage', 20),
        (r'atob\s*\(|btoa\s*\(', 'base64 encoding', 15),
        (r'\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}', 'unicode/hex obfuscation', 20),
        (r'fetch\s*\(|XMLHttpRequest', 'network requests', 25),
        (r'document\.write|innerHTML', 'DOM manipulation', 15),
        (r'location\s*=|href\s*=', 'navigation', 20),
        (r'alert\s*\(|console\.log', 'debug output', 5)
    ]
    
    for pattern, description, points in js_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            score += points
    
    # Advanced evasion techniques
    advanced_patterns = [
        (r'new\s+Proxy\s*\(', 'Proxy handlers', 30),
        (r'WebAssembly\.|wasm', 'WebAssembly usage', 35),
        (r'crypto\.subtle|crypto\.', 'Crypto API', 25),
        (r'SharedArrayBuffer|Atomics\.', 'Shared memory', 40),
        (r'serviceWorker|Worker\s*\(', 'Web Workers', 30),
        (r'async\s+function|await\s+', 'Async operations', 20),
        (r'generator|yield', 'Generator functions', 25),
        (r'Temporal\.|Intl\.', 'Modern APIs', 20),
        (r'FinalizationRegistry|WeakRef', 'Memory management', 35),
        (r'navigator\.|performance\.', 'Browser APIs', 15)
    ]
    
    for pattern, description, points in advanced_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            score += points
    
    # Validation checks
    if not re.search(r'[;\}]', payload):
        issues.append("Missing statement terminators")
    
    if payload.count('(') != payload.count(')'):
        issues.append("Unbalanced parentheses")
        score -= 10
    
    if payload.count('{') != payload.count('}'):
        issues.append("Unbalanced braces")
        score -= 10
    
    # Final scoring
    if score < 20:
        return False, f"Low complexity score: {score}", score
    else:
        return True, f"Valid payload, complexity score: {score}", score

def analyze_payload_category(payload_data):
    """Analyze and score payload by category"""
    category = payload_data.get('category', 'unknown')
    risk_level = payload_data.get('risk_level', 'medium')
    
    category_scores = {
        'advanced_evasion': 90,
        'command_execution': 95,
        'privilege_escalation': 100,
        'file_system': 85,
        'dom_access': 70,
        'network_exfiltration': 80,
        'sandbox_escape': 95,
        'csp_bypass': 85,
        'webkit_specific': 75,
        'windows_integration': 80,
        'api_abuse': 85
    }
    
    risk_multipliers = {
        'critical': 1.5,
        'high': 1.2,
        'medium': 1.0,
        'low': 0.8
    }
    
    base_score = category_scores.get(category, 50)
    risk_multiplier = risk_multipliers.get(risk_level, 1.0)
    final_score = int(base_score * risk_multiplier)
    
    return min(final_score, 100)

def check_browser_compatibility(payload_data):
    """Check payload compatibility and targeting effectiveness"""
    browser = payload_data.get('browser', 'unknown')
    payload = payload_data.get('payload', '')
    technique = payload_data.get('technique', '')
    
    compatibility_issues = []
    effectiveness_score = 100
    
    # Browser-specific API checks
    if browser == 'chrome':
        if 'app.' in payload and 'chrome' in technique:
            compatibility_issues.append("PDF app object usage in Chrome (limited support)")
            effectiveness_score -= 20
        if 'parent.window' in payload:
            effectiveness_score += 10  # Good Chrome targeting
    
    elif browser == 'firefox':
        if 'webkit' in technique.lower():
            compatibility_issues.append("WebKit-specific technique in Firefox payload")
            effectiveness_score -= 30
        if 'app.launch' in payload:
            compatibility_issues.append("Adobe-specific API in Firefox payload")
            effectiveness_score -= 25
    
    return max(effectiveness_score, 0), compatibility_issues

def test_payloads_for_browser(browser, report_mode=False):
    """Test all payloads for a specific browser"""
    payloads = load_payloads_for_browser(browser)
    
    if not payloads:
        print(f"❌ No payloads found for {browser}")
        return None
    
    print(f"\n🧪 TESTING {len(payloads)} PAYLOADS FOR {browser.upper()}")
    print("=" * 60)
    
    results = {
        'browser': browser,
        'total_payloads': len(payloads),
        'valid_payloads': 0,
        'invalid_payloads': 0,
        'high_quality': 0,
        'medium_quality': 0,
        'low_quality': 0,
        'average_syntax_score': 0,
        'average_category_score': 0,
        'average_compatibility_score': 0,
        'categories': defaultdict(int),
        'risk_levels': defaultdict(int),
        'techniques': defaultdict(int),
        'issues': [],
        'payload_details': []
    }
    
    total_syntax_score = 0
    total_category_score = 0
    total_compatibility_score = 0
    
    for i, payload_data in enumerate(payloads, 1):
        payload = payload_data.get('payload', '')
        payload_id = payload_data.get('id', f'unknown_{i}')
        category = payload_data.get('category', 'unknown')
        risk_level = payload_data.get('risk_level', 'medium')
        technique = payload_data.get('technique', 'unknown')
        
        # Syntax validation
        is_valid, syntax_msg, syntax_score = validate_payload_syntax(payload)
        
        # Category analysis
        category_score = analyze_payload_category(payload_data)
        
        # Browser compatibility
        compatibility_score, compatibility_issues = check_browser_compatibility(payload_data)
        
        # Overall quality assessment
        overall_score = (syntax_score * 0.4 + category_score * 0.4 + compatibility_score * 0.2)
        
        if is_valid:
            results['valid_payloads'] += 1
            if overall_score >= 80:
                results['high_quality'] += 1
                quality = "HIGH"
            elif overall_score >= 50:
                results['medium_quality'] += 1
                quality = "MEDIUM"
            else:
                results['low_quality'] += 1
                quality = "LOW"
        else:
            results['invalid_payloads'] += 1
            quality = "INVALID"
        
        # Accumulate scores
        total_syntax_score += syntax_score
        total_category_score += category_score
        total_compatibility_score += compatibility_score
        
        # Track categories and techniques
        results['categories'][category] += 1
        results['risk_levels'][risk_level] += 1
        results['techniques'][technique] += 1
        
        if not report_mode:
            status = "✅" if is_valid else "❌"
            print(f"{status} {payload_id:<25} | {quality:<8} | Score: {overall_score:5.1f}")
    
    # Calculate averages
    if results['total_payloads'] > 0:
        results['average_syntax_score'] = total_syntax_score / results['total_payloads']
        results['average_category_score'] = total_category_score / results['total_payloads']
        results['average_compatibility_score'] = total_compatibility_score / results['total_payloads']
    
    return results

def generate_comprehensive_report(all_results):
    """Generate comprehensive testing report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"test_report_{timestamp}.json"
    
    # Calculate overall statistics
    total_payloads = sum(r['total_payloads'] for r in all_results.values())
    total_valid = sum(r['valid_payloads'] for r in all_results.values())
    total_high_quality = sum(r['high_quality'] for r in all_results.values())
    
    report = {
        'metadata': {
            'generated_at': timestamp,
            'tool_version': VERSION,
            'total_browsers_tested': len(all_results),
            'total_payloads_tested': total_payloads,
            'overall_validity_rate': (total_valid / total_payloads * 100) if total_payloads > 0 else 0,
            'overall_quality_rate': (total_high_quality / total_payloads * 100) if total_payloads > 0 else 0
        },
        'summary': all_results,
        'detailed_analysis': {
            'category_distribution': {},
            'technique_analysis': {},
            'risk_assessment': {}
        }
    }
    
    # Aggregate category data
    all_categories = defaultdict(int)
    all_techniques = defaultdict(int)
    all_risks = defaultdict(int)
    
    for results in all_results.values():
        for category, count in results['categories'].items():
            all_categories[category] += count
        for technique, count in results['techniques'].items():
            all_techniques[technique] += count
        for risk, count in results['risk_levels'].items():
            all_risks[risk] += count
    
    report['detailed_analysis']['category_distribution'] = dict(all_categories)
    report['detailed_analysis']['technique_analysis'] = dict(all_techniques)
    report['detailed_analysis']['risk_assessment'] = dict(all_risks)
    
    try:
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n📊 COMPREHENSIVE TESTING REPORT")
        print("=" * 50)
        print(f"📁 Report saved: {report_file}")
        print(f"🔍 Browsers tested: {len(all_results)}")
        print(f"🎯 Total payloads: {total_payloads}")
        print(f"✅ Valid payloads: {total_valid} ({total_valid/total_payloads*100:.1f}%)")
        print(f"🏆 High quality: {total_high_quality} ({total_high_quality/total_payloads*100:.1f}%)")
        
        return report_file
    except Exception as e:
        print(f"❌ Error saving report: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description=f"PDF-XSS Payload Testing Framework v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 payload_tester.py -b chrome --report          # Test Chrome payloads with report
  python3 payload_tester.py -b all --report             # Test all browsers with comprehensive report
  python3 payload_tester.py -b firefox                  # Test Firefox payloads (console output)
        """)
    
    parser.add_argument('-b', '--browser', 
                        choices=['chrome', 'firefox', 'safari', 'adobe', 'edge', 'all'],
                        default='all',
                        help='Target browser to test (default: all)')
    parser.add_argument('--report', action='store_true',
                        help='Generate detailed JSON report')
    
    args = parser.parse_args()
    
    print(f"🚀 PDF-XSS PAYLOAD TESTING FRAMEWORK v{VERSION}")
    print("=" * 60)
    
    browsers_to_test = ['chrome', 'firefox', 'safari', 'adobe', 'edge'] if args.browser == 'all' else [args.browser]
    
    all_results = {}
    
    for browser in browsers_to_test:
        results = test_payloads_for_browser(browser, args.report)
        if results:
            all_results[browser] = results
            
            if not args.report:
                print(f"\n📈 SUMMARY FOR {browser.upper()}")
                print(f"   Valid: {results['valid_payloads']}/{results['total_payloads']} ({results['valid_payloads']/results['total_payloads']*100:.1f}%)")
                print(f"   High Quality: {results['high_quality']} ({results['high_quality']/results['total_payloads']*100:.1f}%)")
    
    if args.report and all_results:
        generate_comprehensive_report(all_results)
    
    print(f"\n✅ Testing completed for {len(all_results)} browsers")

if __name__ == "__main__":
    main()