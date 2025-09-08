#!/usr/bin/env rust-script

//! Simple test for CIDR IP matching functionality

use std::net::IpAddr;

fn ip_in_cidr(ip: &IpAddr, cidr: &str) -> bool {
    // Proper CIDR matching using ipnetwork crate
    match cidr.parse::<ipnetwork::IpNetwork>() {
        Ok(network) => network.contains(*ip),
        Err(_) => {
            eprintln!("Invalid CIDR notation: {}", cidr);
            false // Safe fallback for invalid CIDR strings
        }
    }
}

fn main() {
    println!("Testing CIDR IP matching functionality...");
    
    // Test IPv4 CIDR matching
    let test_cases = vec![
        // (ip, cidr, expected_match)
        ("192.168.1.1", "192.168.1.0/24", true),
        ("192.168.1.255", "192.168.1.0/24", true),
        ("192.168.2.1", "192.168.1.0/24", false),
        ("10.0.0.1", "10.0.0.0/8", true),
        ("11.0.0.1", "10.0.0.0/8", false),
        ("172.16.0.1", "172.16.0.0/12", true),
        ("172.32.0.1", "172.16.0.0/12", false),
        ("127.0.0.1", "127.0.0.1/32", true),
        ("127.0.0.2", "127.0.0.1/32", false),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (ip_str, cidr, expected) in test_cases {
        let ip: IpAddr = ip_str.parse().unwrap();
        let result = ip_in_cidr(&ip, cidr);
        
        if result == expected {
            println!("✅ PASS: IP {} in CIDR {} -> {}", ip_str, cidr, result);
            passed += 1;
        } else {
            println!("❌ FAIL: IP {} in CIDR {} -> {} (expected {})", ip_str, cidr, result, expected);
            failed += 1;
        }
    }

    // Test invalid CIDR patterns
    let ip = "192.168.1.1".parse::<IpAddr>().unwrap();
    let invalid_cidrs = vec![
        "192.168.1.0/33",  // Invalid subnet mask
        "192.168.1",       // Missing subnet
        "invalid.cidr",    // Invalid format
        "",                // Empty string
    ];

    for invalid_cidr in invalid_cidrs {
        let result = ip_in_cidr(&ip, invalid_cidr);
        if !result {
            println!("✅ PASS: Invalid CIDR '{}' correctly returns false", invalid_cidr);
            passed += 1;
        } else {
            println!("❌ FAIL: Invalid CIDR '{}' should return false", invalid_cidr);
            failed += 1;
        }
    }

    println!("\nResults: {} passed, {} failed", passed, failed);
    
    if failed == 0 {
        println!("🎉 All CIDR tests passed! Implementation is working correctly.");
        std::process::exit(0);
    } else {
        println!("⚠️  Some tests failed. Check implementation.");
        std::process::exit(1);
    }
}