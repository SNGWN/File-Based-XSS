#!/usr/bin/env python3
"""
PDF-XSS Results Analyzer v2.0 - Simplified
===========================================

Simplified results analysis for PDF XSS payload effectiveness tracking.

Features:
- Basic results tracking
- Simple statistics
- Performance analysis
- Lightweight implementation

Author: SNGWN
Version: 2.0
"""

import json
import os
import sys
from datetime import datetime
from collections import defaultdict

def load_test_report(report_file):
    """Load test report from JSON file"""
    if not os.path.exists(report_file):
        print(f"❌ Report file not found: {report_file}")
        return None
    
    try:
        with open(report_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Error loading report: {e}")
        return None

def analyze_browser_performance(report_data):
    """Analyze performance by browser"""
    if 'summary' not in report_data:
        print("❌ Invalid report format")
        return
    
    print("\n📊 BROWSER PERFORMANCE ANALYSIS")
    print("=" * 50)
    
    browsers = [k for k in report_data['summary'].keys() if k != 'overall']
    
    # Sort browsers by average score
    browser_scores = []
    for browser in browsers:
        summary = report_data['summary'][browser]
        browser_scores.append((browser, summary.get('average_score', 0)))
    
    browser_scores.sort(key=lambda x: x[1], reverse=True)
    
    print(f"{'Browser':<10} {'Payloads':<10} {'Valid':<8} {'Avg Score':<10} {'Rating'}")
    print("-" * 55)
    
    for browser, avg_score in browser_scores:
        summary = report_data['summary'][browser]
        total = summary.get('total_payloads', 0)
        valid = summary.get('valid_payloads', 0)
        validity_rate = summary.get('validity_rate', 0)
        
        # Determine rating
        if avg_score >= 80:
            rating = "🔥 Excellent"
        elif avg_score >= 70:
            rating = "✅ Good"
        elif avg_score >= 60:
            rating = "⚠️  Fair"
        else:
            rating = "❌ Poor"
        
        print(f"{browser:<10} {total:<10} {valid:<8} {avg_score:<10.1f} {rating}")

def analyze_payload_categories(report_data):
    """Analyze payload effectiveness by category"""
    print("\n🎯 PAYLOAD CATEGORY ANALYSIS")
    print("=" * 50)
    
    category_stats = defaultdict(lambda: {'count': 0, 'total_score': 0, 'valid_count': 0})
    
    for browser, results in report_data.get('detailed_results', {}).items():
        for result in results:
            category = result.get('category', 'unknown')
            category_stats[category]['count'] += 1
            category_stats[category]['total_score'] += result.get('score', 0)
            if result.get('valid_syntax', False):
                category_stats[category]['valid_count'] += 1
    
    # Sort by average score
    category_list = []
    for category, stats in category_stats.items():
        avg_score = stats['total_score'] / stats['count'] if stats['count'] > 0 else 0
        validity_rate = (stats['valid_count'] / stats['count']) * 100 if stats['count'] > 0 else 0
        category_list.append((category, stats['count'], avg_score, validity_rate))
    
    category_list.sort(key=lambda x: x[2], reverse=True)
    
    print(f"{'Category':<15} {'Count':<8} {'Avg Score':<10} {'Valid%':<8} {'Effectiveness'}")
    print("-" * 65)
    
    for category, count, avg_score, validity_rate in category_list:
        if avg_score >= 75:
            effectiveness = "🔥 High"
        elif avg_score >= 60:
            effectiveness = "✅ Medium"
        else:
            effectiveness = "⚠️  Low"
        
        print(f"{category:<15} {count:<8} {avg_score:<10.1f} {validity_rate:<8.1f} {effectiveness}")

def analyze_evasion_techniques(report_data):
    """Analyze most effective evasion techniques"""
    print("\n🛡️  EVASION TECHNIQUE ANALYSIS")
    print("=" * 50)
    
    technique_stats = defaultdict(lambda: {'count': 0, 'total_score': 0})
    
    for browser, results in report_data.get('detailed_results', {}).items():
        for result in results:
            techniques = result.get('evasion_techniques', [])
            score = result.get('score', 0)
            
            for technique in techniques:
                technique_stats[technique]['count'] += 1
                technique_stats[technique]['total_score'] += score
    
    # Sort by average score
    technique_list = []
    for technique, stats in technique_stats.items():
        avg_score = stats['total_score'] / stats['count'] if stats['count'] > 0 else 0
        technique_list.append((technique, stats['count'], avg_score))
    
    technique_list.sort(key=lambda x: x[2], reverse=True)
    
    print(f"{'Technique':<25} {'Count':<8} {'Avg Score':<10} {'Impact'}")
    print("-" * 55)
    
    for technique, count, avg_score in technique_list[:10]:  # Top 10
        if avg_score >= 80:
            impact = "🔥 High"
        elif avg_score >= 70:
            impact = "✅ Medium"
        else:
            impact = "⚠️  Low"
        
        print(f"{technique:<25} {count:<8} {avg_score:<10.1f} {impact}")

def generate_recommendations(report_data):
    """Generate improvement recommendations"""
    print("\n💡 IMPROVEMENT RECOMMENDATIONS")
    print("=" * 50)
    
    overall = report_data.get('summary', {}).get('overall', {})
    avg_score = overall.get('average_score', 0)
    validity_rate = overall.get('validity_rate', 0)
    
    recommendations = []
    
    if avg_score < 70:
        recommendations.append("🔧 Consider enhancing payload sophistication")
    
    if validity_rate < 80:
        recommendations.append("🔧 Review payload syntax - some payloads may have errors")
    
    # Browser-specific recommendations
    browsers = [k for k in report_data.get('summary', {}).keys() if k != 'overall']
    for browser in browsers:
        browser_data = report_data['summary'][browser]
        if browser_data.get('average_score', 0) < 60:
            recommendations.append(f"🔧 {browser.title()} payloads need improvement")
    
    # Category-specific recommendations
    category_stats = defaultdict(lambda: {'count': 0, 'total_score': 0})
    for browser, results in report_data.get('detailed_results', {}).items():
        for result in results:
            category = result.get('category', 'unknown')
            category_stats[category]['count'] += 1
            category_stats[category]['total_score'] += result.get('score', 0)
    
    for category, stats in category_stats.items():
        avg_score = stats['total_score'] / stats['count'] if stats['count'] > 0 else 0
        if avg_score < 50:
            recommendations.append(f"🔧 {category} category needs more effective payloads")
    
    if not recommendations:
        recommendations.append("✅ Payload database appears to be in good condition")
    
    for rec in recommendations:
        print(f"  {rec}")

def find_latest_report():
    """Find the most recent test report file"""
    report_files = [f for f in os.listdir('.') if f.startswith('test_report_') and f.endswith('.json')]
    
    if not report_files:
        return None
    
    # Sort by filename (which includes timestamp)
    report_files.sort(reverse=True)
    return report_files[0]

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="PDF-XSS Results Analyzer v2.0")
    parser.add_argument('-r', '--report', 
                        help='Test report file to analyze (if not specified, uses latest)')
    parser.add_argument('--categories', action='store_true',
                        help='Show detailed category analysis')
    parser.add_argument('--techniques', action='store_true',
                        help='Show evasion technique analysis')
    parser.add_argument('--recommendations', action='store_true',
                        help='Show improvement recommendations')
    
    args = parser.parse_args()
    
    # Find report file
    if args.report:
        report_file = args.report
    else:
        report_file = find_latest_report()
        if not report_file:
            print("❌ No test report files found. Run payload_tester.py first.")
            return
        print(f"📊 Using latest report: {report_file}")
    
    # Load and analyze report
    report_data = load_test_report(report_file)
    if not report_data:
        return
    
    print("📈 PDF-XSS RESULTS ANALYZER v2.0")
    print("=" * 50)
    
    # Basic analysis
    analyze_browser_performance(report_data)
    
    if args.categories:
        analyze_payload_categories(report_data)
    
    if args.techniques:
        analyze_evasion_techniques(report_data)
    
    if args.recommendations:
        generate_recommendations(report_data)
    
    # Overall summary
    overall = report_data.get('summary', {}).get('overall', {})
    print(f"\n📋 OVERALL SUMMARY")
    print("-" * 20)
    print(f"Total Payloads: {overall.get('total_payloads', 0)}")
    print(f"Valid Payloads: {overall.get('valid_payloads', 0)} ({overall.get('validity_rate', 0):.1f}%)")
    print(f"Average Score: {overall.get('average_score', 0):.1f}/100")

if __name__ == "__main__":
    main()