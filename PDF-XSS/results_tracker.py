#!/usr/bin/env python3
"""
PDF-XSS Results Analysis and Tracking System
=============================================

Comprehensive system for analyzing PDF XSS payload effectiveness,
tracking success rates, and providing actionable insights for
security testing campaigns.

Features:
- Real-time payload effectiveness tracking
- Success rate analysis and trending
- Browser-specific performance metrics
- Automated report generation
- Payload optimization recommendations
- Campaign management and tracking

Author: SNGWN
Version: 1.0
"""

import json
import os
import sys
import time
import statistics
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict
import urllib.parse
import argparse

class PDFXSSResultsTracker:
    """Main class for tracking and analyzing PDF XSS results"""
    
    def __init__(self, db_path="pdf_xss_results.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for results tracking"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                target_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payload_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER,
                payload_id TEXT,
                browser TEXT,
                category TEXT,
                technique TEXT,
                risk_level TEXT,
                quality_score INTEGER,
                execution_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN,
                error_message TEXT,
                response_data TEXT,
                file_path TEXT,
                FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS browser_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                browser TEXT,
                total_payloads INTEGER,
                successful_payloads INTEGER,
                success_rate REAL,
                avg_response_time REAL,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payload_performance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_id TEXT UNIQUE,
                total_executions INTEGER DEFAULT 0,
                successful_executions INTEGER DEFAULT 0,
                success_rate REAL DEFAULT 0.0,
                avg_quality_score REAL DEFAULT 0.0,
                last_executed TIMESTAMP,
                performance_trend TEXT DEFAULT 'stable'
            )
        ''')
        
        conn.commit()
        conn.close()
        print(f"✅ Database initialized: {self.db_path}")
    
    def create_campaign(self, name, description="", target_url=""):
        """Create a new testing campaign"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO campaigns (name, description, target_url)
            VALUES (?, ?, ?)
        ''', (name, description, target_url))
        
        campaign_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        print(f"✅ Campaign created: {name} (ID: {campaign_id})")
        return campaign_id
    
    def log_payload_execution(self, campaign_id, payload_data, success, error_message="", response_data="", file_path=""):
        """Log a payload execution result"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('PRAGMA timeout = 20000')  # 20 seconds timeout
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO payload_executions 
                (campaign_id, payload_id, browser, category, technique, risk_level, quality_score, success, error_message, response_data, file_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                campaign_id,
                payload_data.get('id', ''),
                payload_data.get('browser', ''),
                payload_data.get('category', ''),
                payload_data.get('technique', ''),
                payload_data.get('risk_level', ''),
                payload_data.get('quality_score', 0),
                success,
                error_message,
                response_data,
                file_path
            ))
            
            conn.commit()
            
            # Update payload performance stats
            time.sleep(0.1)  # Small delay to avoid database locks
            self.update_payload_performance(payload_data.get('id', ''), success, payload_data.get('quality_score', 0))
            
        finally:
            conn.close()
    
    def update_payload_performance(self, payload_id, success, quality_score):
        """Update payload performance statistics"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('PRAGMA timeout = 20000')  # 20 seconds timeout
        cursor = conn.cursor()
        
        try:
            # Get current stats
            cursor.execute('SELECT * FROM payload_performance WHERE payload_id = ?', (payload_id,))
            row = cursor.fetchone()
            
            if row:
                # Update existing record
                total_executions = row[2] + 1
                successful_executions = row[3] + (1 if success else 0)
                success_rate = successful_executions / total_executions
                avg_quality_score = (row[4] * row[2] + quality_score) / total_executions
                
                cursor.execute('''
                    UPDATE payload_performance 
                    SET total_executions = ?, successful_executions = ?, success_rate = ?, 
                        avg_quality_score = ?, last_executed = CURRENT_TIMESTAMP
                    WHERE payload_id = ?
                ''', (total_executions, successful_executions, success_rate, avg_quality_score, payload_id))
            else:
                # Create new record
                cursor.execute('''
                    INSERT INTO payload_performance 
                    (payload_id, total_executions, successful_executions, success_rate, avg_quality_score, last_executed)
                    VALUES (?, 1, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (payload_id, 1 if success else 0, 1.0 if success else 0.0, quality_score))
            
            conn.commit()
        finally:
            conn.close()
    
    def analyze_campaign_results(self, campaign_id):
        """Analyze results for a specific campaign"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get campaign info
        cursor.execute('SELECT * FROM campaigns WHERE id = ?', (campaign_id,))
        campaign = cursor.fetchone()
        
        if not campaign:
            print(f"❌ Campaign {campaign_id} not found")
            return None
        
        # Get execution results
        cursor.execute('''
            SELECT browser, category, technique, risk_level, quality_score, success, execution_time
            FROM payload_executions 
            WHERE campaign_id = ?
            ORDER BY execution_time DESC
        ''', (campaign_id,))
        
        results = cursor.fetchall()
        conn.close()
        
        if not results:
            print(f"📊 No execution results found for campaign: {campaign[1]}")
            return None
        
        # Analyze results
        analysis = {
            'campaign_info': {
                'id': campaign[0],
                'name': campaign[1],
                'description': campaign[2],
                'target_url': campaign[3],
                'created_at': campaign[4]
            },
            'summary': {
                'total_executions': len(results),
                'successful_executions': sum(1 for r in results if r[5]),
                'success_rate': sum(1 for r in results if r[5]) / len(results) * 100,
                'avg_quality_score': statistics.mean([r[4] for r in results if r[4] > 0]) if any(r[4] > 0 for r in results) else 0
            },
            'browser_breakdown': {},
            'category_breakdown': {},
            'risk_level_breakdown': {}
        }
        
        # Browser analysis
        browser_stats = defaultdict(lambda: {'total': 0, 'successful': 0})
        for result in results:
            browser = result[0]
            browser_stats[browser]['total'] += 1
            if result[5]:  # success
                browser_stats[browser]['successful'] += 1
        
        for browser, stats in browser_stats.items():
            analysis['browser_breakdown'][browser] = {
                'total': stats['total'],
                'successful': stats['successful'],
                'success_rate': stats['successful'] / stats['total'] * 100 if stats['total'] > 0 else 0
            }
        
        # Category analysis
        category_stats = defaultdict(lambda: {'total': 0, 'successful': 0})
        for result in results:
            category = result[1]
            category_stats[category]['total'] += 1
            if result[5]:  # success
                category_stats[category]['successful'] += 1
        
        for category, stats in category_stats.items():
            analysis['category_breakdown'][category] = {
                'total': stats['total'],
                'successful': stats['successful'],
                'success_rate': stats['successful'] / stats['total'] * 100 if stats['total'] > 0 else 0
            }
        
        # Risk level analysis
        risk_stats = defaultdict(lambda: {'total': 0, 'successful': 0})
        for result in results:
            risk = result[3]
            risk_stats[risk]['total'] += 1
            if result[5]:  # success
                risk_stats[risk]['successful'] += 1
        
        for risk, stats in risk_stats.items():
            analysis['risk_level_breakdown'][risk] = {
                'total': stats['total'],
                'successful': stats['successful'],
                'success_rate': stats['successful'] / stats['total'] * 100 if stats['total'] > 0 else 0
            }
        
        return analysis
    
    def generate_recommendations(self, campaign_id):
        """Generate optimization recommendations based on results"""
        analysis = self.analyze_campaign_results(campaign_id)
        
        if not analysis:
            return []
        
        recommendations = []
        
        # Browser-specific recommendations
        browser_breakdown = analysis['browser_breakdown']
        best_browser = max(browser_breakdown.keys(), key=lambda x: browser_breakdown[x]['success_rate'])
        worst_browser = min(browser_breakdown.keys(), key=lambda x: browser_breakdown[x]['success_rate'])
        
        if browser_breakdown[best_browser]['success_rate'] > browser_breakdown[worst_browser]['success_rate'] + 20:
            recommendations.append({
                'type': 'browser_optimization',
                'priority': 'high',
                'message': f"Focus on {best_browser} payloads (success rate: {browser_breakdown[best_browser]['success_rate']:.1f}%) vs {worst_browser} ({browser_breakdown[worst_browser]['success_rate']:.1f}%)"
            })
        
        # Category-specific recommendations
        category_breakdown = analysis['category_breakdown']
        best_category = max(category_breakdown.keys(), key=lambda x: category_breakdown[x]['success_rate'])
        
        if category_breakdown[best_category]['success_rate'] > 70:
            recommendations.append({
                'type': 'category_focus',
                'priority': 'medium',
                'message': f"'{best_category}' category shows high success rate ({category_breakdown[best_category]['success_rate']:.1f}%) - consider expanding this category"
            })
        
        # Success rate recommendations
        overall_success_rate = analysis['summary']['success_rate']
        
        if overall_success_rate < 30:
            recommendations.append({
                'type': 'payload_quality',
                'priority': 'high',
                'message': f"Low overall success rate ({overall_success_rate:.1f}%) - consider reviewing payload quality and targeting"
            })
        elif overall_success_rate > 80:
            recommendations.append({
                'type': 'security_assessment',
                'priority': 'critical',
                'message': f"High success rate ({overall_success_rate:.1f}%) indicates significant security vulnerabilities"
            })
        
        return recommendations
    
    def export_campaign_report(self, campaign_id, output_file=None):
        """Export comprehensive campaign report"""
        analysis = self.analyze_campaign_results(campaign_id)
        recommendations = self.generate_recommendations(campaign_id)
        
        if not analysis:
            print(f"❌ Cannot generate report for campaign {campaign_id}")
            return False
        
        # Generate report
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'report_version': '1.0',
                'analyzer_version': '1.0'
            },
            'campaign': analysis['campaign_info'],
            'summary': analysis['summary'],
            'detailed_analysis': {
                'browser_breakdown': analysis['browser_breakdown'],
                'category_breakdown': analysis['category_breakdown'],
                'risk_level_breakdown': analysis['risk_level_breakdown']
            },
            'recommendations': recommendations
        }
        
        # Save report
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"campaign_{campaign_id}_report_{timestamp}.json"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Campaign report exported: {output_file}")
            return True
            
        except Exception as e:
            print(f"❌ Error exporting report: {e}")
            return False

def simulate_pdf_testing_campaign():
    """Simulate a PDF testing campaign for demonstration"""
    tracker = PDFXSSResultsTracker()
    
    # Create a test campaign
    campaign_id = tracker.create_campaign(
        "Demo Security Assessment",
        "Demonstration of PDF XSS testing capabilities",
        "https://test-target.example.com"
    )
    
    # Simulate payload executions
    test_payloads = [
        {'id': 'chrome_001', 'browser': 'chrome', 'category': 'dom_access', 'technique': 'parent_window', 'risk_level': 'high', 'quality_score': 85},
        {'id': 'firefox_001', 'browser': 'firefox', 'category': 'csp_bypass', 'technique': 'eval_bypass', 'risk_level': 'medium', 'quality_score': 70},
        {'id': 'safari_001', 'browser': 'safari', 'category': 'file_system', 'technique': 'file_access', 'risk_level': 'critical', 'quality_score': 90},
        {'id': 'adobe_001', 'browser': 'adobe', 'category': 'command_execution', 'technique': 'app_exec', 'risk_level': 'critical', 'quality_score': 95},
        {'id': 'edge_001', 'browser': 'edge', 'category': 'network_exfiltration', 'technique': 'fetch_api', 'risk_level': 'high', 'quality_score': 75}
    ]
    
    import random
    
    print("\n🧪 Simulating payload executions...")
    for i, payload in enumerate(test_payloads):
        success = random.choice([True, True, False])  # 66% success rate
        error_msg = "" if success else "Security policy blocked execution"
        response_data = f"Response data for {payload['id']}" if success else ""
        
        tracker.log_payload_execution(
            campaign_id, payload, success, error_msg, response_data, f"test_{i}.pdf"
        )
        print(f"  {'✅' if success else '❌'} {payload['id']} ({payload['browser']})")
    
    return campaign_id

def main():
    parser = argparse.ArgumentParser(
        description="PDF-XSS Results Analysis and Tracking System v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 results_tracker.py --create-campaign "Web App Test"    # Create new campaign
  python3 results_tracker.py --analyze 1                        # Analyze campaign 1
  python3 results_tracker.py --report 1                         # Generate report for campaign 1
  python3 results_tracker.py --demo                             # Run demonstration

FEATURES:
  ✓ Campaign management and tracking
  ✓ Real-time payload effectiveness analysis
  ✓ Browser-specific performance metrics
  ✓ Automated optimization recommendations
  ✓ Comprehensive report generation
        """
    )
    
    parser.add_argument('--create-campaign', 
                       help='Create a new testing campaign')
    
    parser.add_argument('--analyze', type=int,
                       help='Analyze results for campaign ID')
    
    parser.add_argument('--report', type=int,
                       help='Generate report for campaign ID')
    
    parser.add_argument('--demo', action='store_true',
                       help='Run demonstration with simulated data')
    
    parser.add_argument('--list-campaigns', action='store_true',
                       help='List all campaigns')
    
    args = parser.parse_args()
    
    print("📊 PDF-XSS RESULTS TRACKER v1.0")
    print("=" * 40)
    
    tracker = PDFXSSResultsTracker()
    
    if args.create_campaign:
        campaign_id = tracker.create_campaign(args.create_campaign)
        print(f"Campaign created with ID: {campaign_id}")
    
    elif args.analyze:
        analysis = tracker.analyze_campaign_results(args.analyze)
        if analysis:
            print(f"\n📈 CAMPAIGN ANALYSIS: {analysis['campaign_info']['name']}")
            print("=" * 50)
            print(f"Total Executions: {analysis['summary']['total_executions']}")
            print(f"Success Rate: {analysis['summary']['success_rate']:.1f}%")
            print(f"Avg Quality Score: {analysis['summary']['avg_quality_score']:.1f}")
            
            print("\n🌐 Browser Breakdown:")
            for browser, stats in analysis['browser_breakdown'].items():
                print(f"  {browser.title()}: {stats['successful']}/{stats['total']} ({stats['success_rate']:.1f}%)")
    
    elif args.report:
        success = tracker.export_campaign_report(args.report)
        if success:
            recommendations = tracker.generate_recommendations(args.report)
            if recommendations:
                print("\n💡 RECOMMENDATIONS:")
                for rec in recommendations:
                    priority = rec['priority'].upper()
                    print(f"  [{priority}] {rec['message']}")
    
    elif args.demo:
        print("\n🎯 Running demonstration...")
        campaign_id = simulate_pdf_testing_campaign()
        
        print(f"\n📈 Demo campaign created (ID: {campaign_id})")
        analysis = tracker.analyze_campaign_results(campaign_id)
        
        if analysis:
            print(f"Success Rate: {analysis['summary']['success_rate']:.1f}%")
            print(f"Total Executions: {analysis['summary']['total_executions']}")
        
        tracker.export_campaign_report(campaign_id)
        
        recommendations = tracker.generate_recommendations(campaign_id)
        if recommendations:
            print("\n💡 RECOMMENDATIONS:")
            for rec in recommendations:
                priority = rec['priority'].upper()
                print(f"  [{priority}] {rec['message']}")
    
    elif args.list_campaigns:
        conn = sqlite3.connect(tracker.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, created_at, status FROM campaigns ORDER BY created_at DESC')
        campaigns = cursor.fetchall()
        conn.close()
        
        if campaigns:
            print("\n📋 CAMPAIGNS:")
            for campaign in campaigns:
                print(f"  {campaign[0]}: {campaign[1]} ({campaign[2]}) - {campaign[3]}")
        else:
            print("No campaigns found")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()