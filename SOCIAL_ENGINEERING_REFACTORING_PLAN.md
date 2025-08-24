# Social Engineering Module Refactoring Plan

## Current State Analysis
- **File**: `red-team-exercises/src/scenarios/social_engineering.rs`
- **Size**: 2,966 lines
- **Complexity**: 42 functions, 3 structs, 1 impl block
- **Average Function Size**: ~70 lines per function
- **Issues**: Monolithic design, multiple attack vectors in one file, difficult to maintain

## Refactoring Strategy

### Phase 1: Attack Vector Separation
Break the monolithic file into focused attack vector modules:

#### 1.1 Email-Based Attacks (`social_engineering/email/`)
- `social_engineering/email/mod.rs` - Email attack coordination
- `social_engineering/email/phishing.rs` - Phishing campaigns
- `social_engineering/email/spear_phishing.rs` - Targeted phishing
- `social_engineering/email/bec.rs` - Business Email Compromise
- **Estimated size**: ~800 lines total

#### 1.2 Voice-Based Attacks (`social_engineering/voice/`)
- `social_engineering/voice/mod.rs` - Voice attack coordination
- `social_engineering/voice/vishing.rs` - Voice phishing
- `social_engineering/voice/caller_id_spoofing.rs` - Caller ID manipulation
- `social_engineering/voice/ivr_attacks.rs` - IVR system attacks
- **Estimated size**: ~600 lines total

#### 1.3 Physical Attacks (`social_engineering/physical/`)
- `social_engineering/physical/mod.rs` - Physical attack coordination
- `social_engineering/physical/badge_cloning.rs` - Badge/card attacks
- `social_engineering/physical/tailgating.rs` - Tailgating scenarios
- `social_engineering/physical/device_access.rs` - Physical device access
- **Estimated size**: ~500 lines total

#### 1.4 Digital Pretexting (`social_engineering/pretexting/`)
- `social_engineering/pretexting/mod.rs` - Pretexting coordination
- `social_engineering/pretexting/api_pretexting.rs` - API-based pretexting
- `social_engineering/pretexting/support_pretexting.rs` - Support channel attacks
- `social_engineering/pretexting/credential_recovery.rs` - Password reset attacks
- **Estimated size**: ~600 lines total

#### 1.5 OSINT & Intelligence (`social_engineering/intelligence/`)
- `social_engineering/intelligence/mod.rs` - Intelligence gathering
- `social_engineering/intelligence/osint.rs` - Open source intelligence
- `social_engineering/intelligence/breach_data.rs` - Breach database analysis
- `social_engineering/intelligence/social_media.rs` - Social media reconnaissance
- **Estimated size**: ~400 lines total

#### 1.6 Main Coordinator (`social_engineering/coordinator.rs`)
- `SocialEngineeringOrchestrator` struct
- High-level scenario coordination
- Integration with other modules
- **Estimated size**: ~300 lines

### Phase 2: Common Infrastructure
Extract shared functionality into common modules:

#### 2.1 Attack Templates (`social_engineering/templates/`)
- Email templates for phishing campaigns
- Voice scripts for vishing attacks
- Physical scenario templates
- Pretexting conversation flows

#### 2.2 Target Management (`social_engineering/targets/`)
- Target identification and profiling
- Contact information management
- Attack surface mapping
- Success rate tracking

#### 2.3 Payload Generation (`social_engineering/payloads/`)
- Dynamic payload generation
- Evasion techniques
- Delivery mechanisms
- Tracking and analytics

### Phase 3: Attack Execution Engine
Create a sophisticated execution framework:

#### 3.1 Campaign Management
```rust
pub struct SocialEngineeringCampaign {
    pub id: String,
    pub name: String,
    pub attack_vectors: Vec<AttackVector>,
    pub targets: Vec<Target>,
    pub timeline: CampaignTimeline,
    pub success_metrics: SuccessMetrics,
}
```

#### 3.2 Attack Vector Abstraction
```rust
#[async_trait]
pub trait AttackVector {
    async fn prepare(&mut self, targets: &[Target]) -> Result<()>;
    async fn execute(&self, target: &Target) -> Result<AttackResult>;
    async fn cleanup(&self) -> Result<()>;
    fn get_detection_signatures(&self) -> Vec<DetectionSignature>;
}
```

#### 3.3 Results Analysis
```rust
pub struct AttackAnalyzer {
    pub success_rates: HashMap<AttackType, f64>,
    pub detection_rates: HashMap<AttackType, f64>,
    pub response_times: HashMap<AttackType, Duration>,
    pub recommendations: Vec<SecurityRecommendation>,
}
```

## Implementation Order

### Week 1: Email Attack Vectors
1. Extract email-based attacks to dedicated module
2. Implement phishing campaign management
3. Add spear phishing capabilities
4. Create BEC scenario framework

### Week 2: Voice & Physical Attacks
1. Extract voice-based attacks
2. Implement caller ID spoofing simulation
3. Extract physical attack scenarios
4. Add badge cloning and tailgating tests

### Week 3: Pretexting & Intelligence
1. Extract pretexting scenarios
2. Implement API pretexting framework
3. Add OSINT intelligence gathering
4. Create breach data analysis tools

### Week 4: Integration & Enhancement
1. Create main orchestrator
2. Implement campaign management
3. Add comprehensive reporting
4. Integrate with existing red team framework

## Success Metrics
- **File size reduction**: Target <500 lines per file
- **Function complexity**: Target <50 lines per function
- **Test coverage**: Maintain >80% coverage
- **Attack vector isolation**: Clear separation of concerns
- **Extensibility**: Easy to add new attack types

## Benefits Expected
- **Better Organization**: Clear separation of attack vectors
- **Easier Maintenance**: Focused modules easier to update
- **Enhanced Testing**: Individual attack vectors testable
- **Improved Reusability**: Attack components can be reused
- **Better Documentation**: Each attack vector well-documented
