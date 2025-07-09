#!/usr/bin/env python3
"""
JavaScript minification script for detrackify-email.
Automatically minifies common.js when it changes.
"""

import os
import sys
import time
import hashlib
from pathlib import Path
from rjsmin import jsmin

def get_file_hash(filepath):
    """Get MD5 hash of file content."""
    with open(filepath, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

def minify_js(input_file, output_file):
    """Minify JavaScript file."""
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        minified = jsmin(content)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(minified)
        
        print(f"✓ Minified {input_file} -> {output_file}")
        return True
    except Exception as e:
        print(f"✗ Error minifying {input_file}: {e}")
        return False

def watch_and_minify(templates_dir):
    """Watch for changes and minify automatically."""
    common_js = os.path.join(templates_dir, 'common.js')
    common_js_min = os.path.join(templates_dir, 'common.min.js')
    
    if not os.path.exists(common_js):
        print(f"Error: {common_js} not found")
        return False
    
    # Initial minification
    if minify_js(common_js, common_js_min):
        last_hash = get_file_hash(common_js)
    else:
        return False
    
    print(f"Watching {common_js} for changes... (Press Ctrl+C to stop)")
    
    try:
        while True:
            time.sleep(1)
            if os.path.exists(common_js):
                current_hash = get_file_hash(common_js)
                if current_hash != last_hash:
                    print(f"Change detected in {common_js}")
                    if minify_js(common_js, common_js_min):
                        last_hash = current_hash
            else:
                print(f"Warning: {common_js} was deleted")
                break
    except KeyboardInterrupt:
        print("\nStopped watching for changes.")
    
    return True

def main():
    """Main function."""
    if len(sys.argv) > 1 and sys.argv[1] == '--watch':
        # Watch mode
        templates_dir = 'templates'
        if not os.path.exists(templates_dir):
            print(f"Error: {templates_dir} directory not found")
            sys.exit(1)
        watch_and_minify(templates_dir)
    else:
        # One-time minification
        templates_dir = 'templates'
        common_js = os.path.join(templates_dir, 'common.js')
        common_js_min = os.path.join(templates_dir, 'common.min.js')
        
        if not os.path.exists(common_js):
            print(f"Error: {common_js} not found")
            sys.exit(1)
        
        if minify_js(common_js, common_js_min):
            print("Minification completed successfully")
            sys.exit(0)
        else:
            sys.exit(1)

if __name__ == '__main__':
    main() 