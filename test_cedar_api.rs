use cedar_policy::{Policy, PolicySet};

fn main() {
    let policy_text = r#"
    permit(
        principal == User::"alice",
        action == Action::"read", 
        resource == Profile::"alice"
    );
    "#;
    
    let policy_set = PolicySet::from_str(policy_text).unwrap();
    let policies = policy_set.policies();
    
    for (id, policy) in policies {
        println!("Policy ID: {}", id);
        println!("Policy: {:?}", policy);
        
        // Try to access policy components
        // Check what methods are available
        println!("Policy methods: {:?}", std::any::type_name::<Policy>());
    }
}
