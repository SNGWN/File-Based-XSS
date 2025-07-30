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
    
    # Obfuscation detection
    obfuscation_score = 0
    if len(re.findall(r'\\u[0-9a-fA-F]{4}', payload)) > 10:
        obfuscation_score += 20
    if len(re.findall(r'\\x[0-9a-fA-F]{2}', payload)) > 10:
        obfuscation_score += 20
    if 'atob(' in payload and len(payload) > 200:
        obfuscation_score += 25
    if payload.count('String.fromCharCode') > 0:
        obfuscation_score += 15
    
    score += obfuscation_score
    
    # Complexity analysis
    complexity_score = 0
    if len(payload) > 500:
        complexity_score += 10
    if payload.count('{') > 5:
        complexity_score += 10
    if payload.count('function') > 2:
        complexity_score += 15
    if payload.count('try') > 1:
        complexity_score += 10
    
    score += complexity_score
    
    # Validation checks
    if not re.search(r'[;\}]', payload):
        issues.append("Missing statement terminators")
    
    if payload.count('(') != payload.count(')'):
        issues.append("Unbalanced parentheses")
        score -= 10
    
    if payload.count('{') != payload.count('}'):
        issues.append("Unbalanced braces")
        score -= 10
    
    if payload.count('[') != payload.count(']'):
        issues.append("Unbalanced brackets")
        score -= 5
    
    # Final scoring
    if score < 20:
        return False, f"Low complexity score: {score}, Issues: {', '.join(issues) if issues else 'None'}", score
    elif score < 50:
        return True, f"Medium complexity payload, Issues: {', '.join(issues) if issues else 'None'}", score
    else:
        return True, f"High complexity payload, Issues: {', '.join(issues) if issues else 'None'}", score

def analyze_payload_category(payload_data):
    """Analyze and score payload by category"""
    category = payload_data.get('category', 'unknown')
    technique = payload_data.get('technique', 'unknown')
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
    
    elif browser == 'safari':
        if 'chrome' in technique.lower() or 'pdfi' in technique.lower():
            compatibility_issues.append("Chrome-specific technique in Safari payload")
            effectiveness_score -= 25
    
    elif browser == 'adobe':
        if 'parent.window' in payload:
            compatibility_issues.append("Browser DOM access in Adobe Reader context")
            effectiveness_score -= 15
        if 'app.' in payload:
            effectiveness_score += 15  # Good Adobe targeting
    
    elif browser == 'edge':
        if 'webkit' in technique.lower():
            compatibility_issues.append("WebKit-specific technique in Edge payload")
            effectiveness_score -= 20
    
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
        
        # Store issues
        all_issues = compatibility_issues.copy()
        if not is_valid:
            all_issues.append(syntax_msg)
        
        if all_issues:
            results['issues'].extend(all_issues)
        
        # Store detailed results
        payload_detail = {
            'id': payload_id,
            'category': category,
            'technique': technique,
            'risk_level': risk_level,
            'syntax_score': syntax_score,
            'category_score': category_score,
            'compatibility_score': compatibility_score,
            'overall_score': overall_score,
            'quality': quality,
            'is_valid': is_valid,
            'issues': all_issues
        }
        results['payload_details'].append(payload_detail)
        
        if not report_mode:
            status = "✅" if is_valid else "❌"
            print(f"{status} {payload_id:<25} | {quality:<8} | Score: {overall_score:5.1f} | {syntax_msg}")
    
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
        'recommendations': generate_recommendations(all_results),
        'detailed_analysis': {
            'category_distribution': analyze_category_distribution(all_results),
            'technique_analysis': analyze_technique_distribution(all_results),
            'risk_assessment': analyze_risk_distribution(all_results),
            'browser_comparison': compare_browsers(all_results)
        }
    }
    
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

def generate_recommendations(all_results):
    """Generate improvement recommendations"""
    recommendations = []
    
    for browser, results in all_results.items():
        if results['invalid_payloads'] > 0:
            recommendations.append(f"Fix {results['invalid_payloads']} invalid payloads in {browser}")
        
        if results['low_quality'] > results['high_quality']:
            recommendations.append(f"Improve payload quality in {browser} - more low quality than high quality payloads")
        
        if results['average_compatibility_score'] < 70:
            recommendations.append(f"Improve browser compatibility for {browser} payloads")
        
        # Check for missing categories
        if 'advanced_evasion' not in results['categories']:
            recommendations.append(f"Add advanced evasion techniques for {browser}")
        
        if results['total_payloads'] < 20:
            recommendations.append(f"Expand payload collection for {browser} (currently {results['total_payloads']})")
    
    return recommendations

def analyze_category_distribution(all_results):
    """Analyze payload category distribution across browsers"""
    all_categories = defaultdict(int)
    for results in all_results.values():
        for category, count in results['categories'].items():
            all_categories[category] += count
    return dict(all_categories)

def analyze_technique_distribution(all_results):
    """Analyze technique distribution"""
    all_techniques = defaultdict(int)
    for results in all_results.values():
        for technique, count in results['techniques'].items():
            all_techniques[technique] += count
    return dict(sorted(all_techniques.items(), key=lambda x: x[1], reverse=True)[:20])

def analyze_risk_distribution(all_results):
    """Analyze risk level distribution"""
    all_risks = defaultdict(int)
    for results in all_results.values():
        for risk, count in results['risk_levels'].items():
            all_risks[risk] += count
    return dict(all_risks)

def compare_browsers(all_results):
    """Compare browser payload effectiveness"""
    comparison = {}
    for browser, results in all_results.items():
        comparison[browser] = {
            'payload_count': results['total_payloads'],
            'quality_score': results['average_syntax_score'],
            'compatibility_score': results['average_compatibility_score'],
            'high_quality_percentage': (results['high_quality'] / results['total_payloads'] * 100) if results['total_payloads'] > 0 else 0
        }
    return comparison

def main():
    parser = argparse.ArgumentParser(
        description=f"PDF-XSS Payload Testing Framework v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 payload_tester.py -b chrome --report          # Test Chrome payloads with report
  python3 payload_tester.py -b all --report             # Test all browsers with comprehensive report
  python3 payload_tester.py -b firefox                  # Test Firefox payloads (console output)
  python3 payload_tester.py --report                    # Test all browsers with report (default)

ANALYSIS FEATURES:
  ✓ Syntax validation and complexity scoring
  ✓ Browser compatibility analysis  
  ✓ Payload categorization and risk assessment
  ✓ Technique effectiveness evaluation
  ✓ Comprehensive JSON reporting with recommendations
  ✓ Cross-browser payload comparison
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
                print(f"   Average Scores: Syntax={results['average_syntax_score']:.1f}, Category={results['average_category_score']:.1f}, Compatibility={results['average_compatibility_score']:.1f}")
    
    if args.report and all_results:
        generate_comprehensive_report(all_results)
    
    print(f"\n✅ Testing completed for {len(all_results)} browsers")

if __name__ == "__main__":
    main()
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