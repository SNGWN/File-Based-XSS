#!/usr/bin/env python3
"""
PDF-XSS Results Analyzer v3.0 - Enhanced
===========================================

Enhanced results analysis for PDF XSS payload effectiveness tracking with
comprehensive reporting, trend analysis, and improvement recommendations.

Features:
- Advanced results analysis with statistical insights
- Performance trending and comparison
- Detailed vulnerability assessment
- Payload effectiveness ranking
- Browser-specific optimization recommendations
- Export capabilities for various formats

Author: SNGWN
Version: 3.0
"""

import json
import os
import sys
import argparse
from datetime import datetime
from collections import defaultdict, Counter
import glob

VERSION = "3.0"

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

def find_latest_report():
    """Find the most recent test report"""
    report_files = glob.glob("test_report_*.json")
    if not report_files:
        print("❌ No test reports found")
        return None
    
    # Sort by modification time, get most recent
    latest_file = max(report_files, key=os.path.getmtime)
    print(f"📊 Using latest report: {latest_file}")
    return latest_file

def analyze_browser_performance(report_data):
    """Enhanced browser performance analysis"""
    if 'summary' not in report_data:
        print("❌ Invalid report format")
        return
    
    print("\n📊 BROWSER PERFORMANCE ANALYSIS")
    print("=" * 70)
    
    browsers = [k for k in report_data['summary'].keys() if k != 'overall']
    
    # Enhanced browser comparison
    browser_stats = []
    for browser in browsers:
        data = report_data['summary'][browser]
        stats = {
            'browser': browser,
            'total_payloads': data.get('total_payloads', 0),
            'valid_payloads': data.get('valid_payloads', 0),
            'high_quality': data.get('high_quality', 0),
            'validity_rate': (data.get('valid_payloads', 0) / data.get('total_payloads', 1)) * 100,
            'quality_rate': (data.get('high_quality', 0) / data.get('total_payloads', 1)) * 100,
            'avg_syntax_score': data.get('average_syntax_score', 0),
            'avg_category_score': data.get('average_category_score', 0),
            'avg_compatibility_score': data.get('average_compatibility_score', 0)
        }
        browser_stats.append(stats)
    
    # Sort by overall effectiveness (combination of quality and compatibility)
    browser_stats.sort(key=lambda x: (x['quality_rate'] + x['avg_compatibility_score']) / 2, reverse=True)
    
    print(f"{'Browser':<10} {'Payloads':<9} {'Valid%':<8} {'Quality%':<9} {'Syntax':<8} {'Compat':<8} {'Rank':<6}")
    print("-" * 70)
    
    for i, stats in enumerate(browser_stats, 1):
        effectiveness = (stats['quality_rate'] + stats['avg_compatibility_score']) / 2
        rank = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"#{i}"
        
        print(f"{stats['browser']:<10} {stats['total_payloads']:<9} "
              f"{stats['validity_rate']:<7.1f}% {stats['quality_rate']:<8.1f}% "
              f"{stats['avg_syntax_score']:<7.1f} {stats['avg_compatibility_score']:<7.1f} "
              f"{rank:<6}")
    
    return browser_stats

def analyze_payload_categories(report_data):
    """Analyze payload distribution by categories"""
    if 'detailed_analysis' not in report_data or 'category_distribution' not in report_data['detailed_analysis']:
        print("❌ Category data not available")
        return
    
    print("\n📂 PAYLOAD CATEGORY ANALYSIS")
    print("=" * 50)
    
    categories = report_data['detailed_analysis']['category_distribution']
    total_payloads = sum(categories.values())
    
    # Sort categories by count
    sorted_categories = sorted(categories.items(), key=lambda x: x[1], reverse=True)
    
    print(f"{'Category':<20} {'Count':<8} {'Percentage':<12} {'Visual'}")
    print("-" * 50)
    
    for category, count in sorted_categories:
        percentage = (count / total_payloads) * 100
        bar_length = int(percentage / 5)  # Scale for visual bar
        bar = "█" * bar_length + "░" * (20 - bar_length)
        print(f"{category:<20} {count:<8} {percentage:<11.1f}% {bar}")

def analyze_technique_effectiveness(report_data):
    """Analyze technique effectiveness across browsers"""
    if 'detailed_analysis' not in report_data or 'technique_analysis' not in report_data['detailed_analysis']:
        print("❌ Technique data not available")
        return
    
    print("\n🔧 TECHNIQUE EFFECTIVENESS ANALYSIS")
    print("=" * 60)
    
    techniques = report_data['detailed_analysis']['technique_analysis']
    
    # Show top 10 most used techniques
    sorted_techniques = sorted(techniques.items(), key=lambda x: x[1], reverse=True)[:10]
    
    print(f"{'Technique':<35} {'Usage Count':<12} {'Effectiveness'}")
    print("-" * 60)
    
    for technique, count in sorted_techniques:
        # Estimate effectiveness based on technique type and usage
        effectiveness = "High" if count > 5 and any(keyword in technique.lower() 
                                                    for keyword in ['bypass', 'evasion', 'advanced']) else \
                      "Medium" if count > 2 else "Low"
        
        print(f"{technique[:34]:<35} {count:<12} {effectiveness}")

def analyze_risk_distribution(report_data):
    """Analyze risk level distribution"""
    if 'detailed_analysis' not in report_data or 'risk_assessment' not in report_data['detailed_analysis']:
        print("❌ Risk data not available")
        return
    
    print("\n⚠️  RISK LEVEL DISTRIBUTION")
    print("=" * 40)
    
    risks = report_data['detailed_analysis']['risk_assessment']
    total_payloads = sum(risks.values())
    
    risk_order = ['critical', 'high', 'medium', 'low']
    risk_colors = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
    
    for risk in risk_order:
        count = risks.get(risk, 0)
        percentage = (count / total_payloads) * 100 if total_payloads > 0 else 0
        color = risk_colors.get(risk, '⚪')
        print(f"{color} {risk.capitalize():<10}: {count:>3} payloads ({percentage:5.1f}%)")

def generate_improvement_recommendations(report_data):
    """Generate comprehensive improvement recommendations"""
    print("\n💡 COMPREHENSIVE IMPROVEMENT RECOMMENDATIONS")
    print("=" * 60)
    
    recommendations = []
    
    # Check overall stats
    metadata = report_data.get('metadata', {})
    overall_quality = metadata.get('overall_quality_rate', 0)
    overall_validity = metadata.get('overall_validity_rate', 0)
    
    # General recommendations
    if overall_validity < 90:
        recommendations.append("🔧 Fix payload syntax issues to improve validity rate")
    if overall_quality < 70:
        recommendations.append("⬆️  Enhance payload complexity and obfuscation techniques")
    
    # Browser-specific recommendations
    summary = report_data.get('summary', {})
    for browser, data in summary.items():
        if data.get('total_payloads', 0) < 20:
            recommendations.append(f"📈 Expand {browser} payload collection (currently {data.get('total_payloads', 0)})")
        if data.get('average_compatibility_score', 0) < 70:
            recommendations.append(f"🎯 Improve {browser} browser compatibility")
        if data.get('high_quality', 0) < data.get('total_payloads', 1) * 0.5:
            recommendations.append(f"🏆 Increase high-quality payloads for {browser}")
    
    # Display recommendations
    if recommendations:
        for i, rec in enumerate(recommendations, 1):
            print(f"{i:2d}. {rec}")
    else:
        print("✅ No major improvements needed - payload collection looks comprehensive!")
    
    return recommendations

def main():
    parser = argparse.ArgumentParser(
        description=f"PDF-XSS Results Analyzer v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    
    parser.add_argument('-r', '--report', 
                        help='Specific report file to analyze (default: latest)')
    parser.add_argument('--categories', action='store_true',
                        help='Show detailed category analysis')
    parser.add_argument('--techniques', action='store_true',
                        help='Show technique effectiveness analysis')
    parser.add_argument('--recommendations', action='store_true',
                        help='Show improvement recommendations')
    parser.add_argument('--risks', action='store_true',
                        help='Show risk level distribution')
    parser.add_argument('--all', action='store_true',
                        help='Show all analysis sections')
    
    args = parser.parse_args()
    
    print(f"🚀 PDF-XSS RESULTS ANALYZER v{VERSION}")
    print("=" * 50)
    
    # Load report
    if args.report:
        report_file = args.report
    else:
        report_file = find_latest_report()
    
    if not report_file:
        return
    
    report_data = load_test_report(report_file)
    if not report_data:
        return
    
    # Show basic analysis
    browser_stats = analyze_browser_performance(report_data)
    
    # Show detailed sections based on arguments
    if args.all or args.categories:
        analyze_payload_categories(report_data)
    
    if args.all or args.techniques:
        analyze_technique_effectiveness(report_data)
    
    if args.all or args.risks:
        analyze_risk_distribution(report_data)
    
    if args.all or args.recommendations:
        generate_improvement_recommendations(report_data)
    
    print(f"\n✅ Analysis completed for report: {os.path.basename(report_file)}")

if __name__ == "__main__":
    main()