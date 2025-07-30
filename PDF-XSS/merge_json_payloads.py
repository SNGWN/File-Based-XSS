#!/usr/bin/env python3
"""
Advanced Payload Merger Utility for PDF-XSS Generator
======================================================

Merges and consolidates payload databases from multiple JSON files,
removes duplicates, validates payloads, and creates optimized databases.

Features:
- Intelligent duplicate detection by payload content
- Payload validation and quality scoring
- Browser-specific optimization
- Statistical analysis and reporting
- Enhanced metadata generation

Author: SNGWN
Version: 3.0
"""

import json
import os
import sys
import hashlib
import re
from datetime import datetime
from collections import defaultdict

def hash_payload(payload):
    """Create a hash of the payload for duplicate detection"""
    # Normalize payload by removing whitespace and common variations
    normalized = re.sub(r'\s+', ' ', payload.lower().strip())
    normalized = normalized.replace('http://evil.com/collect', '{url}')
    normalized = normalized.replace('http://test.com', '{url}')
    normalized = normalized.replace('https://webhook.site/test', '{url}')
    return hashlib.md5(normalized.encode()).hexdigest()

def validate_payload(payload_data):
    """Validate payload structure and content"""
    required_fields = ['id', 'category', 'browser', 'technique', 'payload', 'description', 'risk_level']
    
    # Check required fields
    for field in required_fields:
        if field not in payload_data:
            return False, f"Missing required field: {field}"
    
    # Validate payload content
    payload = payload_data['payload']
    if len(payload) < 10:
        return False, "Payload too short"
    
    # Check for suspicious or invalid content
    if not any(char in payload for char in ['(', ')', '{', '}', ';']):
        return False, "Payload doesn't appear to contain valid JavaScript"
    
    # Validate browser field
    valid_browsers = ['chrome', 'firefox', 'safari', 'adobe', 'edge']
    if payload_data['browser'] not in valid_browsers:
        return False, f"Invalid browser: {payload_data['browser']}"
    
    # Validate risk level
    valid_risk_levels = ['low', 'medium', 'high', 'critical']
    if payload_data['risk_level'] not in valid_risk_levels:
        return False, f"Invalid risk level: {payload_data['risk_level']}"
    
    return True, "Valid"

def score_payload_quality(payload_data):
    """Score payload quality based on various factors"""
    score = 0
    payload = payload_data['payload']
    
    # Length scoring (optimal range 100-1000 chars)
    length = len(payload)
    if 100 <= length <= 1000:
        score += 20
    elif 50 <= length < 100 or 1000 < length <= 2000:
        score += 10
    
    # Complexity scoring
    if 'try' in payload and 'catch' in payload:
        score += 15  # Error handling
    
    if 'parent' in payload or 'top' in payload:
        score += 10  # DOM manipulation
    
    if 'atob(' in payload or 'btoa(' in payload:
        score += 10  # Base64 encoding/decoding
    
    if 'eval(' in payload or 'Function(' in payload:
        score += 15  # Dynamic code execution
    
    if any(method in payload for method in ['postMessage', 'XMLHttpRequest', 'fetch']):
        score += 20  # Data exfiltration methods
    
    # Evasion techniques
    if '\\u' in payload:
        score += 10  # Unicode escaping
    
    if any(tech in payload for tech in ['setTimeout', 'setInterval', 'addEventListener']):
        score += 10  # Event-based techniques
    
    # Browser-specific optimizations
    browser = payload_data['browser']
    if browser == 'chrome' and 'PDFium' in payload_data.get('description', ''):
        score += 5
    elif browser == 'firefox' and 'PDF.js' in payload_data.get('description', ''):
        score += 5
    
    # CVE references add credibility
    if payload_data.get('cve_reference') and 'CVE-' in payload_data['cve_reference']:
        score += 15
    
    return min(score, 100)  # Cap at 100

def enhance_payload_metadata(payload_data):
    """Enhance payload with additional metadata"""
    payload = payload_data['payload']
    
    # Detect techniques used
    techniques = []
    if 'parent' in payload or 'top' in payload:
        techniques.append('dom_manipulation')
    if 'postMessage' in payload:
        techniques.append('postmessage_abuse')
    if 'XMLHttpRequest' in payload or 'fetch' in payload:
        techniques.append('network_exfiltration')
    if 'eval(' in payload or 'Function(' in payload:
        techniques.append('dynamic_execution')
    if 'file://' in payload:
        techniques.append('file_access')
    if 'app.alert' in payload:
        techniques.append('pdf_specific')
    
    payload_data['detected_techniques'] = techniques
    payload_data['quality_score'] = score_payload_quality(payload_data)
    payload_data['payload_length'] = len(payload)
    payload_data['last_updated'] = datetime.now().isoformat()
    
    return payload_data

def merge_payloads_from_files(file_list):
    """Merge payloads from multiple JSON files"""
    all_payloads = []
    seen_hashes = set()
    file_stats = {}
    
    for filename in file_list:
        if not os.path.exists(filename):
            print(f"⚠️  File not found: {filename}")
            continue
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
                payloads = data.get('payloads', [])
                
                valid_count = 0
                duplicate_count = 0
                invalid_count = 0
                
                for payload in payloads:
                    # Validate payload
                    is_valid, error_msg = validate_payload(payload)
                    if not is_valid:
                        print(f"❌ Invalid payload in {filename}: {error_msg}")
                        invalid_count += 1
                        continue
                    
                    # Check for duplicates
                    payload_hash = hash_payload(payload['payload'])
                    if payload_hash in seen_hashes:
                        duplicate_count += 1
                        continue
                    
                    seen_hashes.add(payload_hash)
                    
                    # Enhance payload metadata
                    enhanced_payload = enhance_payload_metadata(payload.copy())
                    all_payloads.append(enhanced_payload)
                    valid_count += 1
                
                file_stats[filename] = {
                    'total': len(payloads),
                    'valid': valid_count,
                    'duplicates': duplicate_count,
                    'invalid': invalid_count
                }
                
                print(f"✅ {filename}: {valid_count} valid, {duplicate_count} duplicates, {invalid_count} invalid")
                
        except Exception as e:
            print(f"❌ Error reading {filename}: {e}")
    
    return all_payloads, file_stats

def generate_enhanced_metadata(payloads, file_stats):
    """Generate comprehensive metadata for the merged database"""
    # Count by browser
    browser_counts = defaultdict(int)
    category_counts = defaultdict(int)
    risk_counts = defaultdict(int)
    technique_counts = defaultdict(int)
    
    total_quality_score = 0
    high_quality_count = 0
    
    for payload in payloads:
        browser_counts[payload['browser']] += 1
        category_counts[payload['category']] += 1
        risk_counts[payload['risk_level']] += 1
        
        # Count detected techniques
        for technique in payload.get('detected_techniques', []):
            technique_counts[technique] += 1
        
        # Quality analysis
        quality = payload.get('quality_score', 0)
        total_quality_score += quality
        if quality >= 70:
            high_quality_count += 1
    
    avg_quality = total_quality_score / len(payloads) if payloads else 0
    
    metadata = {
        'generated_at': datetime.now().strftime("%Y%m%d_%H%M%S"),
        'generator_version': '3.0',
        'merge_tool': 'merge_json_payloads.py',
        'total_payloads': len(payloads),
        'average_quality_score': round(avg_quality, 2),
        'high_quality_payloads': high_quality_count,
        'source_files': list(file_stats.keys()),
        'file_statistics': file_stats,
        'breakdown': {
            'browsers': dict(browser_counts),
            'categories': dict(category_counts),
            'risk_levels': dict(risk_counts),
            'detected_techniques': dict(technique_counts)
        },
        'quality_distribution': {
            'excellent': len([p for p in payloads if p.get('quality_score', 0) >= 80]),
            'good': len([p for p in payloads if 60 <= p.get('quality_score', 0) < 80]),
            'fair': len([p for p in payloads if 40 <= p.get('quality_score', 0) < 60]),
            'poor': len([p for p in payloads if p.get('quality_score', 0) < 40])
        }
    }
    
    return metadata

def main():
    print("🔄 ADVANCED PAYLOAD MERGER v3.0")
    print("=" * 45)
    
    # Find all JSON files in current directory
    json_files = [f for f in os.listdir('.') if f.endswith('.json') and f != 'pdf_payloads.json']
    
    if not json_files:
        print("❌ No JSON payload files found in current directory")
        return 1
    
    print(f"📁 Found {len(json_files)} JSON files:")
    for f in json_files:
        print(f"  • {f}")
    print()
    
    # Merge payloads
    print("🔄 Merging payloads...")
    merged_payloads, file_stats = merge_payloads_from_files(json_files)
    
    if not merged_payloads:
        print("❌ No valid payloads found to merge")
        return 1
    
    # Sort payloads by quality score (highest first)
    merged_payloads.sort(key=lambda x: x.get('quality_score', 0), reverse=True)
    
    # Generate metadata
    metadata = generate_enhanced_metadata(merged_payloads, file_stats)
    
    # Create merged database
    merged_database = {
        'metadata': metadata,
        'payloads': merged_payloads
    }
    
    # Save merged database
    output_file = f"pdf_payloads_enhanced_{metadata['generated_at']}.json"
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(merged_database, f, indent=2, ensure_ascii=False)
        
        # Also update the main pdf_payloads.json file
        with open('pdf_payloads.json', 'w', encoding='utf-8') as f:
            json.dump(merged_database, f, indent=2, ensure_ascii=False)
        
        print("\n🎯 MERGE COMPLETE")
        print("=" * 25)
        print(f"✅ Enhanced database saved: {output_file}")
        print(f"✅ Main database updated: pdf_payloads.json")
        print(f"📊 Total payloads: {len(merged_payloads)}")
        print(f"⭐ Average quality score: {metadata['average_quality_score']}")
        print(f"🏆 High quality payloads: {metadata['high_quality_payloads']}")
        print()
        print("📈 Quality Distribution:")
        for level, count in metadata['quality_distribution'].items():
            print(f"  {level.title()}: {count}")
        print()
        print("🎯 Browser Distribution:")
        for browser, count in metadata['breakdown']['browsers'].items():
            print(f"  {browser.title()}: {count}")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error saving merged database: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())