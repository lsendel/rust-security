# SOAR Case Management Refactoring Plan

## Current State Analysis
- **File**: `auth-service/src/soar_case_management.rs`
- **Size**: 4,128 lines
- **Complexity**: 137 structs, 82 enums, 20 impl blocks, 33 functions
- **Issues**: Monolithic design, multiple responsibilities, difficult to maintain

## Refactoring Strategy

### Phase 1: Module Decomposition
Break the monolithic file into focused modules:

#### 1.1 Core Types Module (`soar/case_types.rs`)
- `SecurityCase` and related core types
- `CaseStatus`, `CasePriority`, `CasePhase` enums
- Basic case data structures
- **Estimated size**: ~300 lines

#### 1.2 Template System (`soar/templates/`)
- `soar/templates/mod.rs` - Template management
- `soar/templates/automation.rs` - Automation rules
- `soar/templates/assignment.rs` - Assignment rules
- `soar/templates/escalation.rs` - Escalation policies
- **Estimated size**: ~800 lines total

#### 1.3 Evidence Management (`soar/evidence/`)
- `soar/evidence/mod.rs` - Evidence manager
- `soar/evidence/storage.rs` - Storage configuration
- `soar/evidence/encryption.rs` - Encryption handling
- `soar/evidence/chain_of_custody.rs` - Custody tracking
- **Estimated size**: ~600 lines total

#### 1.4 SLA Management (`soar/sla/`)
- `soar/sla/mod.rs` - SLA tracker
- `soar/sla/policies.rs` - SLA policies
- `soar/sla/escalation.rs` - SLA escalation
- **Estimated size**: ~400 lines total

#### 1.5 Collaboration System (`soar/collaboration/`)
- `soar/collaboration/mod.rs` - Collaboration manager
- `soar/collaboration/communication.rs` - Communication templates
- `soar/collaboration/notifications.rs` - Notification system
- **Estimated size**: ~500 lines total

#### 1.6 Quality Assurance (`soar/quality/`)
- `soar/quality/mod.rs` - QA system
- `soar/quality/checklist.rs` - Quality checklists
- `soar/quality/metrics.rs` - Quality metrics
- **Estimated size**: ~300 lines total

#### 1.7 Main Case Manager (`soar/case_manager.rs`)
- `CaseManagementSystem` struct
- High-level case operations
- Integration with other modules
- **Estimated size**: ~400 lines

### Phase 2: Function Decomposition
Break down large functions (>50 lines) into smaller, focused functions:

#### 2.1 Case Creation Functions
- Split complex case creation logic
- Separate validation, template application, and persistence
- Extract automation rule processing

#### 2.2 Case Processing Functions
- Break down case update operations
- Separate state transitions from business logic
- Extract notification logic

#### 2.3 Evidence Processing Functions
- Split evidence collection and validation
- Separate encryption from storage operations
- Extract chain of custody updates

### Phase 3: Trait Extraction
Extract common behaviors into traits:

#### 3.1 Case Operations Trait
```rust
#[async_trait]
pub trait CaseOperations {
    async fn create_case(&self, request: CreateCaseRequest) -> Result<SecurityCase>;
    async fn update_case(&self, id: &str, update: CaseUpdate) -> Result<SecurityCase>;
    async fn close_case(&self, id: &str, reason: CloseReason) -> Result<()>;
}
```

#### 3.2 Evidence Operations Trait
```rust
#[async_trait]
pub trait EvidenceOperations {
    async fn collect_evidence(&self, case_id: &str, evidence: Evidence) -> Result<String>;
    async fn verify_evidence(&self, evidence_id: &str) -> Result<bool>;
    async fn chain_custody(&self, evidence_id: &str, action: CustodyAction) -> Result<()>;
}
```

### Phase 4: Error Handling Improvement
- Create specific error types for each module
- Implement proper error propagation
- Add context to errors for better debugging

### Phase 5: Testing Strategy
- Unit tests for each module
- Integration tests for cross-module interactions
- Mock implementations for external dependencies

## Implementation Order

### Week 1: Core Infrastructure
1. Create module structure
2. Extract core types to `case_types.rs`
3. Set up proper module exports
4. Ensure compilation

### Week 2: Template System
1. Extract template-related code
2. Implement template automation
3. Add template validation
4. Update tests

### Week 3: Evidence & SLA Systems
1. Extract evidence management
2. Implement SLA tracking
3. Add proper error handling
4. Update integration points

### Week 4: Collaboration & Quality
1. Extract collaboration features
2. Implement quality assurance
3. Add notification system
4. Final integration testing

## Success Metrics
- **File size reduction**: Target <500 lines per file
- **Cyclomatic complexity**: Target <10 per function
- **Test coverage**: Maintain >80% coverage
- **Compilation time**: Improve by 20%+
- **Maintainability**: Clear module boundaries

## Risk Mitigation
- **Incremental approach**: Refactor one module at a time
- **Comprehensive testing**: Maintain test coverage throughout
- **Feature flags**: Use feature flags for gradual rollout
- **Rollback plan**: Keep original file until refactoring is complete

## Tools and Automation
- Use `cargo-modules` to visualize module structure
- Implement automated complexity checking
- Set up pre-commit hooks for module size limits
- Add CI checks for refactoring compliance
