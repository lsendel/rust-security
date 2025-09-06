use axum::{
    body::Body,
    http::{Method, Request},
    Router,
};
use tower::ServiceExt;

// Local lightweight mocks implementing the public service traits
mod local_mocks {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Arc;

    pub struct MockAuthService;
    impl MockAuthService {
        pub fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl auth_service::services::AuthServiceTrait for MockAuthService {
        async fn login(
            &self,
            _request: auth_service::services::auth_service::LoginRequest,
        ) -> Result<
            auth_service::services::auth_service::LoginResponse,
            auth_service::shared::error::AppError,
        > {
            Ok(auth_service::services::auth_service::LoginResponse {
                user: auth_service::services::auth_service::UserInfo {
                    id: "test-user-id".into(),
                    email: "test@example.com".into(),
                    name: "Test User".into(),
                    roles: vec!["user".into()],
                    verified: true,
                    last_login: None,
                },
                session_id: "test-session-id".into(),
                access_token: "mock_access_token".into(),
                refresh_token: "mock_refresh_token".into(),
                expires_in: 3600,
            })
        }
        async fn logout(
            &self,
            _session_id: &str,
        ) -> Result<(), auth_service::shared::error::AppError> {
            Ok(())
        }
        async fn validate_session(
            &self,
            _session_id: &str,
        ) -> Result<
            auth_service::services::auth_service::UserInfo,
            auth_service::shared::error::AppError,
        > {
            Ok(auth_service::services::auth_service::UserInfo {
                id: "test-user-id".into(),
                email: "test@example.com".into(),
                name: "Test User".into(),
                roles: vec!["user".into()],
                verified: true,
                last_login: None,
            })
        }
        async fn refresh_token(
            &self,
            _refresh_token: &str,
        ) -> Result<
            auth_service::services::auth_service::LoginResponse,
            auth_service::shared::error::AppError,
        > {
            Err(auth_service::shared::error::AppError::InvalidCredentials)
        }
    }

    pub struct MockUserService;
    impl MockUserService {
        pub fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl auth_service::services::user_service::UserServiceTrait for MockUserService {
        async fn register(
            &self,
            request: auth_service::services::user_service::RegisterRequest,
        ) -> Result<
            auth_service::services::user_service::UserResponse,
            auth_service::services::user_service::UserError,
        > {
            Ok(auth_service::services::user_service::UserResponse {
                id: "user-1".into(),
                email: request.email,
                name: Some(request.name),
                verified: true,
                created_at: chrono::Utc::now(),
            })
        }
        async fn get_profile(
            &self,
            _user_id: &auth_service::domain::value_objects::UserId,
        ) -> Result<
            auth_service::services::user_service::UserResponse,
            auth_service::services::user_service::UserError,
        > {
            Err(auth_service::services::user_service::UserError::NotFound)
        }
        async fn update_profile(
            &self,
            _user_id: &auth_service::domain::value_objects::UserId,
            _request: auth_service::services::user_service::UpdateProfileRequest,
        ) -> Result<
            auth_service::services::user_service::UserResponse,
            auth_service::services::user_service::UserError,
        > {
            Err(auth_service::services::user_service::UserError::NotFound)
        }
        async fn delete_user(
            &self,
            _user_id: &auth_service::domain::value_objects::UserId,
        ) -> Result<(), auth_service::services::user_service::UserError> {
            Ok(())
        }
    }

    pub struct MockTokenService;
    impl MockTokenService {
        pub fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl auth_service::services::token_service::TokenServiceTrait for MockTokenService {
        async fn revoke_token(
            &self,
            _token_hash: &str,
        ) -> Result<(), auth_service::services::token_service::TokenError> {
            Ok(())
        }
        async fn revoke_all_user_tokens(
            &self,
            _user_id: &auth_service::domain::value_objects::UserId,
        ) -> Result<(), auth_service::services::token_service::TokenError> {
            Ok(())
        }
        async fn validate_token(
            &self,
            _token_hash: &str,
        ) -> Result<
            auth_service::domain::entities::Token,
            auth_service::services::token_service::TokenError,
        > {
            Err(auth_service::services::token_service::TokenError::NotFound)
        }
        async fn cleanup_expired_tokens(
            &self,
        ) -> Result<i64, auth_service::services::token_service::TokenError> {
            Ok(0)
        }
        async fn get_user_tokens(
            &self,
            _user_id: &auth_service::domain::value_objects::UserId,
        ) -> Result<
            Vec<auth_service::domain::entities::Token>,
            auth_service::services::token_service::TokenError,
        > {
            Ok(vec![])
        }
    }
}

// Build a Router using local mocks and AppContainer wiring
pub fn make_auth_router() -> Router {
    use auth_service::app::di::AppContainer;
    use auth_service::services::token_service::TokenServiceTrait;
    use auth_service::services::user_service::UserServiceTrait;
    use auth_service::services::AuthServiceTrait;
    use std::sync::Arc;

    let metrics =
        auth_service::infrastructure::monitoring::MetricsCollector::new().expect("metrics");
    let health = auth_service::infrastructure::monitoring::HealthChecker::new();

    let container = AppContainer {
        user_service: Arc::new(local_mocks::MockUserService::new()) as Arc<dyn UserServiceTrait>,
        auth_service: Arc::new(local_mocks::MockAuthService::new()) as Arc<dyn AuthServiceTrait>,
        token_service: Arc::new(local_mocks::MockTokenService::new()) as Arc<dyn TokenServiceTrait>,
        metrics_collector: Arc::new(metrics),
        health_checker: Arc::new(health),
    };

    auth_service::app::router::create_router(container)
}

pub async fn request(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<&str>,
) -> axum::http::Response<axum::body::Body> {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(match body {
            Some(b) => Body::from(b.to_string()),
            None => Body::empty(),
        })
        .unwrap();

    app.clone().oneshot(req).await.unwrap()
}
