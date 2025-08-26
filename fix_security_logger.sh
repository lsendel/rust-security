#!/bin/bash

# Fix SecurityLogger imports in auth-service
cd /Users/lsendel/IdeaProjects/rust-security

# Find all files with SecurityLogger imports and fix them
grep -r "SecurityLogger" auth-service/src/ | grep "use.*SecurityLogger" | cut -d: -f1 | sort -u | while read file; do
    echo "Fixing $file"
    sed -i '' 's/use crate::security_logging::{SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity};/use crate::security_logging::{SecurityEvent, SecurityEventType, SecuritySeverity};/g' "$file"
done

echo "Fixed SecurityLogger imports"
