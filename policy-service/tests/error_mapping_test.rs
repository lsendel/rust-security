use axum::http::StatusCode;
use policy_service::errors::{AppError, AuthorizationError, ConfigError, EntityError, PolicyError};

#[test]
fn not_found_variants_map_to_404() {
    let e1 = AppError::from(PolicyError::NotFound { id: "p1".into() });
    let e2 = AppError::from(EntityError::NotFound {
        entity_type: "User".into(),
        entity_id: "u1".into(),
    });
    let e3 = AppError::PolicyNotFound;
    assert_eq!(e1.status_code(), StatusCode::NOT_FOUND);
    assert_eq!(e2.status_code(), StatusCode::NOT_FOUND);
    assert_eq!(e3.status_code(), StatusCode::NOT_FOUND);
}

#[test]
fn bad_request_group_maps_to_400() {
    let e1 = AppError::from(PolicyError::ValidationFailed { reason: "x".into() });
    let e2 = AppError::from(EntityError::ValidationFailed { reason: "y".into() });
    let e3 = AppError::from(AuthorizationError::InvalidAction {
        action: "read".into(),
    });
    let e4 = AppError::InvalidInput("bad".into());
    assert_eq!(e1.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(e2.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(e3.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(e4.status_code(), StatusCode::BAD_REQUEST);
}

#[test]
fn internal_group_maps_to_500() {
    let e1 = AppError::Config(ConfigError::MissingRequired { key: "k".into() });
    let e2 = AppError::Internal {
        context: "oops".into(),
    };
    let e3 = AppError::InternalServerError;
    assert_eq!(e1.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(e2.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(e3.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
}
