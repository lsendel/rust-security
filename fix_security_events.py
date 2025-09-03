#!/usr/bin/env python3
import re
import sys

def fix_security_event_chains(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Pattern to match logger.log_event with SecurityEvent chain
    pattern = r'logger\.log_event\(\s*&SecurityEvent::new\((.*?)\)\s*\);'
    
    def replace_chain(match):
        inner_content = match.group(1)
        # Extract the SecurityEvent constructor and method chains
        lines = match.group(0).split('\n')
        
        # Find the method chains
        chain_start = None
        for i, line in enumerate(lines):
            if 'SecurityEvent::new(' in line:
                chain_start = i
                break
        
        if chain_start is None:
            return match.group(0)
        
        # Reconstruct with proper variable assignment
        result = []
        result.append('let event = SecurityEvent::new(')
        
        # Add the constructor parameters
        constructor_lines = []
        method_lines = []
        in_constructor = True
        
        for line in lines[chain_start:]:
            if in_constructor and ')' in line and '.with_' not in line:
                constructor_lines.append(line.split(')')[0] + ')')
                in_constructor = False
                if '.with_' in line:
                    method_lines.append(line.split('.with_')[1:])
            elif '.with_' in line:
                method_lines.extend([m for m in line.split('.with_') if m])
            elif not in_constructor:
                method_lines.append(line.strip())
        
        # This is getting complex, let's use a simpler approach
        return match.group(0)
    
    # For now, let's manually fix the known patterns
    fixes = [
        # Fix the method chain issue by creating a variable first
        (
            r'logger\.log_event\(\s*&SecurityEvent::new\(',
            'let event = SecurityEvent::new('
        ),
        (
            r'(\s+)\.with_([^)]+\))\s*\);',
            r'\1.with_\2;\n            logger.log_event(&event);'
        )
    ]
    
    for pattern, replacement in fixes:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)
    
    with open(file_path, 'w') as f:
        f.write(content)

if __name__ == '__main__':
    fix_security_event_chains('./auth-service/src/infrastructure/storage/session/manager.rs')
    print("Fixed SecurityEvent reference issues")
