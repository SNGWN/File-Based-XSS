#!/usr/bin/env python3
"""
Merge Multiple Payload JSON Files
================================

This script merges all existing payload JSON files into a single consolidated file,
ensuring no duplicates and preserving all unique payloads.
"""

import json
import os
import glob
from datetime import datetime

def load_json_file(filepath):
    """Load a JSON file and return its content"""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Error loading {filepath}: {e}")
        return None

def merge_payload_files():
    """Merge all payload JSON files in the repository"""
    print("🔄 MERGING PAYLOAD JSON FILES")
    print("=" * 40)
    
    # Find all JSON files in the repository
    json_files = []
    
    # Check root directory
    root_files = glob.glob('/home/runner/work/XSS-PDF/XSS-PDF/*.json')
    json_files.extend(root_files)
    
    # Check PDF directory
    pdf_files = glob.glob('/home/runner/work/XSS-PDF/XSS-PDF/PDF/*.json')
    json_files.extend(pdf_files)
    
    print(f"📁 Found {len(json_files)} JSON files:")
    for f in json_files:
        print(f"   - {os.path.basename(f)}")
    
    if not json_files:
        print("❌ No JSON files found to merge")
        return
    
    # Load all JSON files
    all_data = []
    total_payloads = 0
    
    for json_file in json_files:
        print(f"\n📖 Loading {os.path.basename(json_file)}...")
        data = load_json_file(json_file)
        
        if data and 'payloads' in data:
            payloads = data['payloads']
            print(f"   Found {len(payloads)} payloads")
            all_data.append(data)
            total_payloads += len(payloads)
        elif data:
            print(f"   ⚠️  No 'payloads' key found in {os.path.basename(json_file)}")
        
    if not all_data:
        print("❌ No valid payload data found in JSON files")
        return
    
    # Merge all payloads and remove duplicates
    print(f"\n🔄 Merging {total_payloads} payloads from {len(all_data)} files...")
    
    merged_payloads = []
    seen_payloads = set()  # Track unique payloads by (browser, technique, payload) combination
    
    for data in all_data:
        for payload in data['payloads']:
            # Create a unique identifier for the payload
            unique_key = (
                payload.get('browser', ''),
                payload.get('technique', ''),
                payload.get('payload', '')
            )
            
            if unique_key not in seen_payloads:
                seen_payloads.add(unique_key)
                merged_payloads.append(payload)
            # else: duplicate found, skip it
    
    print(f"✅ Merged to {len(merged_payloads)} unique payloads")
    print(f"🗑️  Removed {total_payloads - len(merged_payloads)} duplicates")
    
    # Create comprehensive metadata
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Analyze merged payloads
    browsers = {}
    categories = {}
    risk_levels = {}
    
    for payload in merged_payloads:
        browser = payload.get('browser', 'unknown')
        category = payload.get('category', 'unknown')
        risk = payload.get('risk_level', 'unknown')
        
        browsers[browser] = browsers.get(browser, 0) + 1
        categories[category] = categories.get(category, 0) + 1
        risk_levels[risk] = risk_levels.get(risk, 0) + 1
    
    # Create merged data structure
    merged_data = {
        'metadata': {
            'generated_at': timestamp,
            'total_payloads': len(merged_payloads),
            'source_files': [os.path.basename(f) for f in json_files],
            'original_total': total_payloads,
            'duplicates_removed': total_payloads - len(merged_payloads),
            'generator_version': '2.0',
            'merge_tool': 'merge_json_payloads.py',
            'breakdown': {
                'browsers': browsers,
                'categories': categories,
                'risk_levels': risk_levels
            }
        },
        'payloads': merged_payloads
    }
    
    # Save merged file
    output_file = f'/home/runner/work/XSS-PDF/XSS-PDF/merged_payload_database_{timestamp}.json'
    
    try:
        with open(output_file, 'w') as f:
            json.dump(merged_data, f, indent=2)
        
        print(f"\n💾 MERGE COMPLETE")
        print(f"📄 Saved to: {os.path.basename(output_file)}")
        print(f"📊 Final statistics:")
        print(f"   Total unique payloads: {len(merged_payloads)}")
        print(f"   Browsers: {dict(sorted(browsers.items()))}")
        print(f"   Categories: {dict(sorted(categories.items()))}")
        print(f"   Risk levels: {dict(sorted(risk_levels.items()))}")
        
        # Optionally show some sample payloads
        print(f"\n📋 Sample payloads:")
        for i, payload in enumerate(merged_payloads[:3]):
            print(f"   {i+1}. {payload.get('browser', 'N/A')} - {payload.get('technique', 'N/A')}")
            print(f"      {payload.get('description', 'No description')[:60]}...")
        
        if len(merged_payloads) > 3:
            print(f"   ... and {len(merged_payloads) - 3} more payloads")
            
    except Exception as e:
        print(f"❌ Error saving merged file: {e}")

if __name__ == "__main__":
    merge_payload_files()