#![no_main]

use libfuzzer_sys::fuzz_target;
use input_validation::parsers::{OAuthParser, SafeParser, ParserConfig};

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string
    if let Ok(input) = std::str::from_utf8(data) {
        // Skip inputs that are too large
        if input.len() > 10000 {
            return;
        }
        
        // Create parser
        if let Ok(parser) = OAuthParser::new(ParserConfig::production()) {
            // Parse the input - we don't care about the result, just that it doesn't crash
            let _ = parser.parse(input);
        }
    }
});
