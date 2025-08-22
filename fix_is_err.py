#!/usr/bin/env python3

import re

# Read the file
with open('auth-service/src/lib.rs', 'r') as f:
    content = f.read()

# Fix patterns like .is_err().is_err()
content = re.sub(r'\.is_err\(\)\s*\.is_err\(\)', '', content)

# Fix patterns where .is_err() is called on Results that should be matched directly
# This is more complex and needs manual review, but let's fix obvious cases

# Write back
with open('auth-service/src/lib.rs', 'w') as f:
    f.write(content)

print("Fixed double .is_err() patterns")
