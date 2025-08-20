#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use auth_service::scim_filter::{parse_filter, FilterExpression, ComparisonOperator, LogicalOperator};

#[derive(Arbitrary, Debug)]
struct ScimFilterInput {
    filter: String,
    attribute: String,
    value: String,
    operator: u8,  // Maps to operators
}

impl ScimFilterInput {
    fn get_comparison_operator(&self) -> &str {
        match self.operator % 8 {
            0 => "eq",
            1 => "ne", 
            2 => "co",
            3 => "sw",
            4 => "ew",
            5 => "gt",
            6 => "ge",
            7 => "lt",
            _ => "le",
        }
    }

    fn get_logical_operator(&self) -> &str {
        match self.operator % 3 {
            0 => "and",
            1 => "or",
            _ => "not",
        }
    }
}

// Fuzz SCIM filter parsing - the main attack surface
fuzz_target!(|input: ScimFilterInput| {
    // Test direct filter parsing - should never panic
    let _ = parse_filter(&input.filter);
    
    // Test constructed filters with various operators
    let comparison_op = input.get_comparison_operator();
    let constructed_filter = format!("{} {} \"{}\"", input.attribute, comparison_op, input.value);
    let _ = parse_filter(&constructed_filter);
    
    // Test with logical operators
    let logical_op = input.get_logical_operator();
    let complex_filter = format!("{} {} \"{}\" {} {} {} \"{}\"", 
        input.attribute, comparison_op, input.value,
        logical_op,
        input.attribute, comparison_op, input.value
    );
    let _ = parse_filter(&complex_filter);
});

// Fuzz with raw bytes to test malformed filters
fuzz_target!(|data: &[u8]| {
    let filter_str = String::from_utf8_lossy(data);
    
    // Test parsing - should handle all input gracefully
    let _ = parse_filter(&filter_str);
    
    // Test with URL encoding (common in HTTP requests)
    let url_encoded = urlencoding::encode(&filter_str);
    let _ = parse_filter(&url_encoded);
    
    // Test with double encoding
    let double_encoded = urlencoding::encode(&url_encoded);
    let _ = parse_filter(&double_encoded);
});

// Fuzz with common SCIM filter patterns
fuzz_target!(|data: &[u8]| {
    if !data.is_empty() {
        let base = String::from_utf8_lossy(data);
        
        // Common SCIM filter patterns that might cause issues
        let filter_patterns = vec![
            // Basic equality
            format!("userName eq \"{}\"", base),
            format!("emails[type eq \"work\"].value eq \"{}\"", base),
            
            // Complex attribute paths
            format!("addresses[type eq \"work\"].{} eq \"{}\"", base, base),
            format!("phoneNumbers[primary eq true].{} eq \"{}\"", base, base),
            
            // Nested filters
            format!("userName eq \"{}\" and active eq true", base),
            format!("(userName eq \"{}\" or email eq \"{}\") and active eq true", base, base),
            
            // String operations
            format!("userName co \"{}\"", base),
            format!("displayName sw \"{}\"", base),
            format!("email ew \"{}\"", base),
            
            // Presence filters
            format!("{} pr", base),
            format!("emails[{} pr].value pr", base),
            
            // Numeric comparisons
            format!("meta.created gt \"{}\"", base),
            format!("meta.version ge \"{}\"", base),
            
            // Special characters and edge cases
            format!("userName eq \"{}\"", base.replace('"', "\\\"")),
            format!("path eq \"{}\"", base.replace('\\', "\\\\")),
            
            // Potential injection attempts
            format!("userName eq \"\\\"; DROP TABLE users; -- {}\"", base),
            format!("filter eq \"{}\" OR 1=1", base),
            
            // Unicode and international characters
            format!("displayName eq \"{}\"", format!("测试{}", base)),
            format!("title co \"{}\"", format!("Niño{}", base)),
            
            // Long attribute paths
            format!("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:{} eq \"{}\"", base, base),
        ];
        
        for pattern in filter_patterns {
            let _ = parse_filter(&pattern);
        }
    }
});

// Fuzz filter length limits and performance
fuzz_target!(|data: &[u8]| {
    if !data.is_empty() {
        let base_filter = String::from_utf8_lossy(data);
        
        // Test with various lengths to check for DoS
        for multiplier in [1, 10, 100, 1000] {
            let large_filter = base_filter.repeat(multiplier);
            
            // Test parsing with time limits
            let start = std::time::Instant::now();
            let _ = parse_filter(&large_filter);
            let duration = start.elapsed();
            
            // Log potential DoS issues (won't panic in fuzzing)
            if duration.as_millis() > 100 && multiplier > 1 {
                eprintln!("Slow filter parsing: {}ms for {} chars ({}x multiplier)", 
                         duration.as_millis(), large_filter.len(), multiplier);
            }
            
            // Break early if parsing is getting too slow
            if duration.as_secs() > 1 {
                break;
            }
        }
    }
});

// Fuzz nested parentheses and complex expressions
fuzz_target!(|data: &[u8]| {
    if data.len() >= 3 {
        let attr = String::from_utf8_lossy(&data[0..data.len()/3]);
        let op = String::from_utf8_lossy(&data[data.len()/3..2*data.len()/3]);
        let value = String::from_utf8_lossy(&data[2*data.len()/3..]);
        
        // Test deeply nested expressions
        let mut nested_filter = format!("{} eq \"{}\"", attr, value);
        
        for depth in 1..=5 {
            nested_filter = format!("({} and {})", nested_filter, format!("{} eq \"{}\"", attr, value));
            let _ = parse_filter(&nested_filter);
            
            // Test with OR operations too
            let or_filter = format!("({} or {})", nested_filter, format!("{} eq \"{}\"", attr, value));
            let _ = parse_filter(&or_filter);
            
            // Test with NOT operations
            let not_filter = format!("not ({})", nested_filter);
            let _ = parse_filter(&not_filter);
        }
    }
});

// Fuzz bracket expressions (array filters)
fuzz_target!(|data: &[u8]| {
    let base = String::from_utf8_lossy(data);
    
    if !base.is_empty() {
        // Test various bracket expressions that are common in SCIM
        let bracket_patterns = vec![
            format!("emails[type eq \"work\"].value eq \"{}\"", base),
            format!("addresses[primary eq true].{} eq \"{}\"", base, base),
            format!("phoneNumbers[{} eq \"mobile\"].value pr", base),
            format!("groups[display co \"{}\"].value pr", base),
            
            // Nested brackets
            format!("members[emails[type eq \"work\"].value eq \"{}\"].display pr", base),
            
            // Multiple conditions in brackets
            format!("emails[type eq \"work\" and primary eq true].value eq \"{}\"", base),
            format!("addresses[type eq \"home\" or primary eq true].{} eq \"{}\"", base, base),
            
            // Edge cases with brackets
            format!("{}[{}].{} eq \"{}\"", base, base, base, base),
            format!("attr[{}]", base),
            format!("attr[].value eq \"{}\"", base),
            format!("attr[eq \"{}\"", base), // Malformed - missing closing bracket
            format!("attr type eq \"{}\"]", base), // Malformed - missing opening bracket
            
            // Deeply nested brackets
            format!("a[b[c[d eq \"{}\"].e eq \"{}\"].f eq \"{}\"].g eq \"{}\"", base, base, base, base),
        ];
        
        for pattern in bracket_patterns {
            let _ = parse_filter(&pattern);
        }
    }
});

// Fuzz attribute path parsing
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    
    // Test various attribute path formats
    let path_patterns = vec![
        text.to_string(),
        format!("{}.{}", text, text),
        format!("{}.{}.{}", text, text, text),
        format!("urn:ietf:params:scim:schemas:core:2.0:User:{}", text),
        format!("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:{}", text),
        
        // With special characters
        format!("{}_test", text),
        format!("{}$ref", text),
        format!("{}.$$", text),
        
        // Edge cases
        format!(".{}", text),
        format!("{}.", text),
        format!("..{}", text),
        format!("{}..", text),
        "".to_string(),
        ".".to_string(),
        "..".to_string(),
    ];
    
    for path in path_patterns {
        if !path.is_empty() {
            let filter = format!("{} eq \"test\"", path);
            let _ = parse_filter(&filter);
            
            let pr_filter = format!("{} pr", path);
            let _ = parse_filter(&pr_filter);
        }
    }
});

// Fuzz quoted string parsing
fuzz_target!(|data: &[u8]| {
    let content = String::from_utf8_lossy(data);
    
    // Test various quoting scenarios
    let quote_patterns = vec![
        format!("attr eq \"{}\"", content),
        format!("attr eq '{}'", content), // Single quotes (if supported)
        format!("attr eq \"{}\"", content.replace('"', "\\\"")), // Escaped quotes
        format!("attr eq \"{}\"", content.replace('\\', "\\\\")), // Escaped backslashes
        
        // Unterminated quotes
        format!("attr eq \"{})", content),
        format!("attr eq \"{}", content),
        format!("attr eq {}", content), // No quotes
        
        // Empty quotes
        "attr eq \"\"".to_string(),
        "attr eq ''".to_string(),
        
        // Unicode in quotes
        format!("attr eq \"{}测试\"", content),
        format!("attr eq \"{}🔒\"", content),
        
        // Control characters
        format!("attr eq \"{}\"", content.replace('\n', "\\n")),
        format!("attr eq \"{}\"", content.replace('\t', "\\t")),
        format!("attr eq \"{}\"", content.replace('\r', "\\r")),
    ];
    
    for pattern in quote_patterns {
        let _ = parse_filter(&pattern);
    }
});