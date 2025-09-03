//! Mock implementations for testing
//!
//! This module provides mock implementations of all the major services
//! and repositories used by the application. These mocks are designed
//! for unit testing and integration testing without requiring external
//! dependencies like databases.

pub mod auth_service;
pub mod health_checker;
pub mod metrics_collector;
pub mod token_service;
pub mod user_service;
