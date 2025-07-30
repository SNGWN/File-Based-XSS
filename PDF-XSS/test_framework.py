#!/usr/bin/env python3
"""
PDF-XSS Testing and Validation Framework
=========================================

Comprehensive testing framework for PDF XSS payloads with browser automation,
result analysis, and payload effectiveness tracking.

Features:
- Automated PDF generation and testing
- Browser compatibility validation
- Payload effectiveness scoring
- Result analysis and reporting
- Performance benchmarking
- Security assessment

Author: SNGWN
Version: 1.0
"""

import argparse
import json
import os
import sys
import subprocess
import time
import hashlib
import platform
from datetime import datetime
from urllib.parse import urlparse, parse_qs

def load_payloads_database():
    """Load the main payloads database"""
    database_file = 'pdf_payloads.json'
    
    if not os.path.exists(database_file):
        print(f"❌ Database file not found: {database_file}")
        return None
    
    try:
        with open(database_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data
    except Exception as e:
        print(f"❌ Error loading database: {e}")
        return None

def validate_payload_syntax(payload):
    """Validate JavaScript payload syntax"""
    # Basic syntax validation
    if not payload:
        return False, "Empty payload"
    
    # Check for balanced parentheses
    paren_count = payload.count('(') - payload.count(')')
    if paren_count != 0:
        return False, f"Unbalanced parentheses: {paren_count}"
    
    # Check for balanced braces
    brace_count = payload.count('{') - payload.count('}')
    if brace_count != 0:
        return False, f"Unbalanced braces: {brace_count}"
    
    # Check for basic JavaScript keywords
    js_keywords = ['function', 'var', 'try', 'catch', 'if', 'for', 'while']
    if not any(keyword in payload.lower() for keyword in js_keywords):
        return False, "No JavaScript keywords detected"
    
    return True, "Valid syntax"

def analyze_payload_techniques(payload):
    """Analyze techniques used in payload"""
    techniques = {
        'dom_manipulation': ['parent', 'top', 'window', 'document'],
        'data_exfiltration': ['XMLHttpRequest', 'fetch', 'sendBeacon', 'postMessage'],
        'evasion': ['atob', 'btoa', 'eval', 'Function', 'setTimeout'],
        'encoding': ['\\u', 'String.fromCharCode', 'unescape', 'decodeURI'],
        'pdf_specific': ['app.alert', 'app.getURL', 'this.submitForm'],
        'modern_apis': ['ServiceWorker', 'SharedArrayBuffer', 'WebAssembly', 'BroadcastChannel'],
        'persistence': ['localStorage', 'sessionStorage', 'indexedDB'],
        'error_handling': ['try', 'catch', 'throw']
    }
    
    detected = {}
    for category, keywords in techniques.items():
        detected[category] = sum(1 for keyword in keywords if keyword in payload)
    
    return detected

def calculate_payload_complexity(payload):
    """Calculate payload complexity score"""
    complexity_score = 0
    
    # Length factor (normalized)
    length_score = min(len(payload) / 100, 10)
    complexity_score += length_score
    
    # Nested functions
    function_count = payload.count('function')
    complexity_score += function_count * 2
    
    # Try-catch blocks
    try_catch_count = payload.count('try')
    complexity_score += try_catch_count * 3
    
    # Conditional statements
    if_count = payload.count('if(')
    complexity_score += if_count * 1
    
    # Loops
    loop_count = payload.count('for(') + payload.count('while(')
    complexity_score += loop_count * 2
    
    # API calls
    api_calls = ['XMLHttpRequest', 'fetch', 'postMessage', 'addEventListener']
    api_score = sum(1 for api in api_calls if api in payload)
    complexity_score += api_score * 2
    
    return min(complexity_score, 50)  # Cap at 50

def test_pdf_generation(browser, count=5):
    """Test PDF generation for a specific browser"""
    print(f"\n🧪 TESTING PDF GENERATION - {browser.upper()}")
    print("=" * 50)
    
    start_time = time.time()
    
    # Test script.py
    try:
        cmd = [sys.executable, 'script.py', '-b', browser, '--count', str(count), '-u', 'http://test-validation.com']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"✅ script.py generation successful for {browser}")
            files_generated = len([f for f in os.listdir('Files') if f.startswith(browser)])
            print(f"📁 Files generated: {files_generated}")
        else:
            print(f"❌ script.py generation failed for {browser}")
            print(f"Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"⏰ script.py generation timed out for {browser}")
        return False
    except Exception as e:
        print(f"❌ Error testing script.py: {e}")
        return False
    
    # Test Another-Script.py
    try:
        cmd = [sys.executable, 'Another-Script.py', '-b', browser, '-u', 'http://test-validation.com']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"✅ Another-Script.py generation successful for {browser}")
        else:
            print(f"❌ Another-Script.py generation failed for {browser}")
            print(f"Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"⏰ Another-Script.py generation timed out for {browser}")
        return False
    except Exception as e:
        print(f"❌ Error testing Another-Script.py: {e}")
        return False
    
    generation_time = time.time() - start_time
    print(f"⏱️  Generation time: {generation_time:.2f} seconds")
    
    return True

def analyze_payload_database():
    """Comprehensive analysis of the payload database"""
    print("\n📊 PAYLOAD DATABASE ANALYSIS")
    print("=" * 40)
    
    database = load_payloads_database()
    if not database:
        return False
    
    payloads = database.get('payloads', [])
    metadata = database.get('metadata', {})
    
    print(f"📁 Database version: {metadata.get('generator_version', 'Unknown')}")
    print(f"📊 Total payloads: {len(payloads)}")
    print(f"⭐ Average quality score: {metadata.get('average_quality_score', 'N/A')}")
    print()
    
    # Syntax validation
    valid_count = 0
    invalid_payloads = []
    
    for i, payload_data in enumerate(payloads):
        payload = payload_data.get('payload', '')
        is_valid, error = validate_payload_syntax(payload)
        
        if is_valid:
            valid_count += 1
        else:
            invalid_payloads.append({
                'id': payload_data.get('id', f'payload_{i}'),
                'error': error,
                'browser': payload_data.get('browser', 'unknown')
            })
    
    print(f"✅ Valid payloads: {valid_count}/{len(payloads)} ({valid_count/len(payloads)*100:.1f}%)")
    
    if invalid_payloads:
        print(f"❌ Invalid payloads: {len(invalid_payloads)}")
        for invalid in invalid_payloads[:5]:  # Show first 5
            print(f"  • {invalid['id']} ({invalid['browser']}): {invalid['error']}")
        if len(invalid_payloads) > 5:
            print(f"  ... and {len(invalid_payloads) - 5} more")
    
    # Technique analysis
    print("\n🔍 TECHNIQUE ANALYSIS")
    print("-" * 25)
    
    all_techniques = {}
    complexity_scores = []
    
    for payload_data in payloads:
        payload = payload_data.get('payload', '')
        techniques = analyze_payload_techniques(payload)
        complexity = calculate_payload_complexity(payload)
        complexity_scores.append(complexity)
        
        for category, count in techniques.items():
            if count > 0:
                all_techniques[category] = all_techniques.get(category, 0) + count
    
    # Sort techniques by frequency
    sorted_techniques = sorted(all_techniques.items(), key=lambda x: x[1], reverse=True)
    
    for technique, count in sorted_techniques:
        print(f"  {technique.replace('_', ' ').title()}: {count}")
    
    # Complexity analysis
    avg_complexity = sum(complexity_scores) / len(complexity_scores) if complexity_scores else 0
    print(f"\n📈 Average complexity score: {avg_complexity:.2f}/50")
    
    # Browser distribution
    print("\n🌐 BROWSER DISTRIBUTION")
    print("-" * 25)
    browser_counts = {}
    for payload_data in payloads:
        browser = payload_data.get('browser', 'unknown')
        browser_counts[browser] = browser_counts.get(browser, 0) + 1
    
    for browser, count in sorted(browser_counts.items(), key=lambda x: x[1], reverse=True):
        percentage = count / len(payloads) * 100
        print(f"  {browser.title()}: {count} ({percentage:.1f}%)")
    
    return True

def benchmark_performance():
    """Benchmark PDF generation performance"""
    print("\n⚡ PERFORMANCE BENCHMARK")
    print("=" * 30)
    
    browsers = ['chrome', 'firefox', 'safari', 'adobe', 'edge']
    results = {}
    
    for browser in browsers:
        print(f"\n🔬 Benchmarking {browser}...")
        
        # Benchmark script.py
        start_time = time.time()
        try:
            cmd = [sys.executable, 'script.py', '-b', browser, '--count', '3', '-u', 'http://benchmark.test']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            script_time = time.time() - start_time
            script_success = result.returncode == 0
        except:
            script_time = None
            script_success = False
        
        # Benchmark Another-Script.py
        start_time = time.time()
        try:
            cmd = [sys.executable, 'Another-Script.py', '-b', browser, '-u', 'http://benchmark.test']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            another_time = time.time() - start_time
            another_success = result.returncode == 0
        except:
            another_time = None
            another_success = False
        
        results[browser] = {
            'script_time': script_time,
            'script_success': script_success,
            'another_time': another_time,
            'another_success': another_success
        }
        
        # Display results
        if script_success:
            print(f"  ✅ script.py: {script_time:.2f}s")
        else:
            print(f"  ❌ script.py: Failed")
            
        if another_success:
            print(f"  ✅ Another-Script.py: {another_time:.2f}s")
        else:
            print(f"  ❌ Another-Script.py: Failed")
    
    # Summary
    print("\n📈 PERFORMANCE SUMMARY")
    print("-" * 25)
    
    successful_browsers = [b for b, r in results.items() if r['script_success'] and r['another_success']]
    
    if successful_browsers:
        avg_script_time = sum(results[b]['script_time'] for b in successful_browsers) / len(successful_browsers)
        avg_another_time = sum(results[b]['another_time'] for b in successful_browsers) / len(successful_browsers)
        
        print(f"Average script.py time: {avg_script_time:.2f}s")
        print(f"Average Another-Script.py time: {avg_another_time:.2f}s")
        print(f"Successful browsers: {len(successful_browsers)}/{len(browsers)}")
    else:
        print("❌ No successful benchmarks")
    
    return results

def generate_test_report():
    """Generate comprehensive test report"""
    print("\n📋 GENERATING TEST REPORT")
    print("=" * 35)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"test_report_{timestamp}.json"
    
    # Collect test data
    database = load_payloads_database()
    if not database:
        print("❌ Cannot generate report without database")
        return False
    
    payloads = database.get('payloads', [])
    
    # Validate all payloads
    validation_results = []
    for payload_data in payloads:
        payload = payload_data.get('payload', '')
        is_valid, error = validate_payload_syntax(payload)
        techniques = analyze_payload_techniques(payload)
        complexity = calculate_payload_complexity(payload)
        
        validation_results.append({
            'id': payload_data.get('id'),
            'browser': payload_data.get('browser'),
            'category': payload_data.get('category'),
            'is_valid': is_valid,
            'error': error if not is_valid else None,
            'techniques': techniques,
            'complexity': complexity,
            'quality_score': payload_data.get('quality_score', 0)
        })
    
    # Generate report
    report = {
        'metadata': {
            'generated_at': timestamp,
            'test_framework_version': '1.0',
            'database_version': database.get('metadata', {}).get('generator_version', 'Unknown'),
            'total_payloads_tested': len(payloads),
            'platform': platform.system(),
            'python_version': sys.version
        },
        'validation_summary': {
            'valid_payloads': sum(1 for r in validation_results if r['is_valid']),
            'invalid_payloads': sum(1 for r in validation_results if not r['is_valid']),
            'average_complexity': sum(r['complexity'] for r in validation_results) / len(validation_results),
            'average_quality_score': sum(r['quality_score'] for r in validation_results) / len(validation_results)
        },
        'browser_breakdown': {},
        'technique_analysis': {},
        'detailed_results': validation_results
    }
    
    # Browser breakdown
    for browser in ['chrome', 'firefox', 'safari', 'adobe', 'edge']:
        browser_payloads = [r for r in validation_results if r['browser'] == browser]
        if browser_payloads:
            report['browser_breakdown'][browser] = {
                'total': len(browser_payloads),
                'valid': sum(1 for r in browser_payloads if r['is_valid']),
                'average_complexity': sum(r['complexity'] for r in browser_payloads) / len(browser_payloads),
                'average_quality': sum(r['quality_score'] for r in browser_payloads) / len(browser_payloads)
            }
    
    # Save report
    try:
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Test report saved: {report_file}")
        print(f"📊 Tested {len(payloads)} payloads")
        print(f"✅ Valid: {report['validation_summary']['valid_payloads']}")
        print(f"❌ Invalid: {report['validation_summary']['invalid_payloads']}")
        print(f"📈 Avg Complexity: {report['validation_summary']['average_complexity']:.2f}")
        print(f"⭐ Avg Quality: {report['validation_summary']['average_quality_score']:.2f}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error saving report: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PDF-XSS Testing and Validation Framework v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 test_framework.py --analyze              # Analyze payload database
  python3 test_framework.py --test chrome          # Test Chrome PDF generation
  python3 test_framework.py --benchmark            # Run performance benchmark  
  python3 test_framework.py --report               # Generate comprehensive report
  python3 test_framework.py --full-test            # Run all tests

FEATURES:
  ✓ Payload syntax validation
  ✓ Technique analysis and categorization
  ✓ Browser compatibility testing
  ✓ Performance benchmarking
  ✓ Comprehensive reporting
        """
    )
    
    parser.add_argument('--analyze', action='store_true',
                       help='Analyze payload database quality and techniques')
    
    parser.add_argument('--test', choices=['chrome', 'firefox', 'safari', 'adobe', 'edge', 'all'],
                       help='Test PDF generation for specific browser(s)')
    
    parser.add_argument('--benchmark', action='store_true',
                       help='Run performance benchmark tests')
    
    parser.add_argument('--report', action='store_true',
                       help='Generate comprehensive test report')
    
    parser.add_argument('--full-test', action='store_true',
                       help='Run complete test suite (analyze + test + benchmark + report)')
    
    parser.add_argument('--count', type=int, default=3,
                       help='Number of PDFs to generate per browser for testing (default: 3)')
    
    args = parser.parse_args()
    
    if not any(vars(args).values()):
        parser.print_help()
        return 1
    
    print("🧪 PDF-XSS TESTING FRAMEWORK v1.0")
    print("=" * 45)
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Working Directory: {os.getcwd()}")
    print()
    
    success = True
    
    if args.full_test or args.analyze:
        success = analyze_payload_database() and success
    
    if args.full_test or args.test:
        browsers = ['chrome', 'firefox', 'safari', 'adobe', 'edge'] if args.test == 'all' or args.full_test else [args.test]
        for browser in browsers:
            success = test_pdf_generation(browser, args.count) and success
    
    if args.full_test or args.benchmark:
        benchmark_performance()
    
    if args.full_test or args.report:
        success = generate_test_report() and success
    
    print("\n🎯 TESTING COMPLETE")
    print("=" * 20)
    
    if success:
        print("✅ All tests passed successfully")
        return 0
    else:
        print("❌ Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())