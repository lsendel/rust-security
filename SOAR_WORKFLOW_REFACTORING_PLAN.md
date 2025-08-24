# SOAR Workflow Orchestration Refactoring Plan

## Current State Analysis
- **File**: `auth-service/src/soar_workflow.rs`
- **Size**: 1,956 lines
- **Complexity**: 32 structs, 9 enums, 9 impl blocks, 30 functions
- **Average Function Size**: ~65 lines per function
- **Issues**: Complex orchestration logic, multiple responsibilities, difficult to test

## Refactoring Strategy

### Phase 1: Core Component Separation
Break the monolithic workflow orchestrator into focused components:

#### 1.1 Workflow Engine Core (`soar/workflow/`)
- `soar/workflow/mod.rs` - Main workflow coordination
- `soar/workflow/engine.rs` - Core execution engine
- `soar/workflow/instance.rs` - Workflow instance management
- `soar/workflow/context.rs` - Execution context handling
- **Estimated size**: ~600 lines total

#### 1.2 Step Execution System (`soar/workflow/execution/`)
- `soar/workflow/execution/mod.rs` - Execution coordination
- `soar/workflow/execution/executor.rs` - Step executor registry
- `soar/workflow/execution/parallel.rs` - Parallel execution logic
- `soar/workflow/execution/retry.rs` - Retry and error handling
- **Estimated size**: ~400 lines total

#### 1.3 Approval Management (`soar/workflow/approval/`)
- `soar/workflow/approval/mod.rs` - Approval coordination
- `soar/workflow/approval/manager.rs` - Approval manager
- `soar/workflow/approval/policies.rs` - Approval policies
- `soar/workflow/approval/escalation.rs` - Escalation handling
- **Estimated size**: ~350 lines total

#### 1.4 Scheduling System (`soar/workflow/scheduling/`)
- `soar/workflow/scheduling/mod.rs` - Scheduling coordination
- `soar/workflow/scheduling/scheduler.rs` - Workflow scheduler
- `soar/workflow/scheduling/recurring.rs` - Recurring workflows
- `soar/workflow/scheduling/triggers.rs` - Trigger management
- **Estimated size**: ~300 lines total

#### 1.5 Persistence Layer (`soar/workflow/persistence/`)
- `soar/workflow/persistence/mod.rs` - Persistence coordination
- `soar/workflow/persistence/state.rs` - State management
- `soar/workflow/persistence/checkpoints.rs` - Checkpoint handling
- `soar/workflow/persistence/recovery.rs` - Recovery mechanisms
- **Estimated size**: ~250 lines total

#### 1.6 Metrics & Monitoring (`soar/workflow/metrics/`)
- `soar/workflow/metrics/mod.rs` - Metrics coordination
- `soar/workflow/metrics/collector.rs` - Metrics collection
- `soar/workflow/metrics/analyzer.rs` - Performance analysis
- `soar/workflow/metrics/reporting.rs` - Metrics reporting
- **Estimated size**: ~200 lines total

### Phase 2: Advanced Features Extraction
Extract sophisticated features into dedicated modules:

#### 2.1 Template Engine Integration
```rust
pub struct WorkflowTemplateEngine {
    handlebars: Handlebars<'static>,
    template_cache: HashMap<String, CompiledTemplate>,
    variable_resolver: VariableResolver,
}
```

#### 2.2 Risk Assessment System
```rust
pub struct WorkflowRiskAssessor {
    risk_factors: Vec<RiskFactor>,
    scoring_rules: Vec<ScoringRule>,
    calculation_model: RiskCalculationModel,
}
```

#### 2.3 Circuit Breaker Pattern
```rust
pub struct WorkflowCircuitBreaker {
    config: CircuitBreakerConfig,
    state: CircuitBreakerState,
    failure_tracker: FailureTracker,
}
```

### Phase 3: Orchestration Architecture
Create a clean orchestration layer:

#### 3.1 Main Orchestrator
```rust
pub struct WorkflowOrchestrator {
    engine: Arc<WorkflowEngine>,
    scheduler: Arc<WorkflowScheduler>,
    approval_manager: Arc<ApprovalManager>,
    metrics_collector: Arc<MetricsCollector>,
    persistence_layer: Arc<PersistenceLayer>,
}
```

#### 3.2 Component Integration
```rust
#[async_trait]
pub trait WorkflowComponent {
    async fn initialize(&mut self) -> Result<()>;
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    fn get_health_status(&self) -> ComponentHealth;
}
```

## Implementation Order

### Week 1: Core Engine Extraction
1. Extract workflow engine core
2. Implement instance management
3. Create execution context handling
4. Set up basic orchestration

### Week 2: Execution System
1. Extract step execution logic
2. Implement parallel execution
3. Add retry mechanisms
4. Create error handling framework

### Week 3: Approval & Scheduling
1. Extract approval management
2. Implement approval policies
3. Create scheduling system
4. Add recurring workflow support

### Week 4: Persistence & Metrics
1. Extract persistence layer
2. Implement state management
3. Add metrics collection
4. Create monitoring dashboards

## Success Metrics
- **File size reduction**: Target <400 lines per file
- **Component isolation**: Clear separation of concerns
- **Test coverage**: >85% coverage per module
- **Performance**: No degradation in execution speed
- **Maintainability**: Easier to understand and modify

## Benefits Expected
- **Better Organization**: Clear separation of workflow concerns
- **Enhanced Testing**: Individual components testable
- **Improved Performance**: Optimized execution paths
- **Easier Maintenance**: Focused modules easier to update
- **Better Monitoring**: Component-specific metrics
