#!/usr/bin/env python3

import re

def fix_syntax_errors(file_path):
    """Fix common syntax errors in Rust files where braces and parentheses are mixed up."""

    with open(file_path, 'r') as f:
        content = f.read()

    original_content = content

    # Fix function signatures: } -> should be ) ->
    content = re.sub(r'}\s*->', r') ->', content)

    # Fix closing braces at end of lines that should be parentheses
    # This is tricky - we need to be careful not to break valid syntax
    # Let's fix specific patterns we know are wrong

    # Fix: Ok((}} should be Ok(())
    content = re.sub(r'Ok\(\(\}\}', r'Ok(())', content)

    # Fix: .to_string(} should be .to_string()
    content = re.sub(r'\.to_string\(\}', r'.to_string()', content)

    # Fix: .as_bytes(} should be .as_bytes()
    content = re.sub(r'\.as_bytes\(\}', r'.as_bytes()', content)

    # Fix: .await?} should be .await?)
    content = re.sub(r'\.await\?\}', r'.await?)', content)

    # Fix: ;} should be ;) for statement endings
    content = re.sub(r';\}', r';)', content)

    # Fix: (} should be ()
    content = re.sub(r'\(\}', r'()', content)

    # Fix: {method} should be {method}
    content = re.sub(r'\{method\}', r'{method}', content)

    # Fix: {path} should be {path}
    content = re.sub(r'\{path\}', r'{path}', content)

    # Fix: {nonce} should be {nonce}
    content = re.sub(r'\{nonce\}', r'{nonce}', content)

    # Fix: {timestamp} should be {timestamp}
    content = re.sub(r'\{timestamp\}', r'{timestamp}', content)

    # Write back if changes were made
    if content != original_content:
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"Fixed syntax errors in {file_path}")
        return True
    else:
        print(f"No syntax errors found in {file_path}")
        return False

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python fix_syntax.py <file_path>")
        sys.exit(1)

    fix_syntax_errors(sys.argv[1])
