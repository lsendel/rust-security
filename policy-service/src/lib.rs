use axum::http;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use cedar_policy::{Authorizer, Context, Entities, PolicySet, Request};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tower_http::cors::{Any, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use utoipa::ToSchema;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl From<cedar_policy::ParseErrors> for PolicyError {
    fn from(err: cedar_policy::ParseErrors) -> Self {
        PolicyError::Parse(err.to_string())
    }
}

impl IntoResponse for PolicyError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            PolicyError::Io(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("IO error: {}", err),
            ),
            PolicyError::Parse(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Parse error: {}", err),
            ),
            PolicyError::Internal(err) => {
                tracing::error!("Internal error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };

        (status, message).into_response()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeRequest {
    pub request_id: String,
    pub principal: serde_json::Value,
    pub action: String,
    pub resource: serde_json::Value,
    pub context: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeResponse {
    pub decision: String,
}

pub struct AppState {
    pub authorizer: Authorizer,
    pub policies: PolicySet,
    pub entities: Entities,
}

pub fn load_policies_and_entities() -> Result<Arc<AppState>, PolicyError> {
    let policies_path = concat!(env!("CARGO_MANIFEST_DIR"), "/policies.cedar");
    let policies_str = std::fs::read_to_string(policies_path)?;
    let policies = policies_str.parse::<PolicySet>()?;
    let entities_path = concat!(env!("CARGO_MANIFEST_DIR"), "/entities.json");
    let entities_str = std::fs::read_to_string(entities_path)?;
    let entities = Entities::from_json_str(&entities_str, None)
        .map_err(|e| PolicyError::Parse(e.to_string()))?;

    Ok(Arc::new(AppState {
        authorizer: Authorizer::new(),
        policies,
        entities,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/authorize",
    request_body = AuthorizeRequest,
    responses((status = 200, description = "Authorization decision", body = AuthorizeResponse))
)]
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthorizeRequest>,
) -> Result<Json<AuthorizeResponse>, PolicyError> {
    let action = cedar_policy::EntityUid::from_json(serde_json::json!({
        "type": "Action",
        "id": body.action
    }))
    .map_err(|e| PolicyError::Parse(e.to_string()))?;
    let principal = parse_entity(&body.principal)?;
    let resource = parse_entity(&body.resource)?;
    let context = Context::from_json_value(body.context, None)
        .map_err(|e| PolicyError::Parse(e.to_string()))?;
    let request = Request::new(Some(principal), Some(action), Some(resource), context, None)
        .map_err(|e| PolicyError::Parse(e.to_string()))?;
    let decision = state
        .authorizer
        .is_authorized(&request, &state.policies, &state.entities)
        .decision();
    let decision_str = if decision == cedar_policy::Decision::Allow {
        "Allow"
    } else {
        "Deny"
    };
    Ok(Json(AuthorizeResponse {
        decision: decision_str.to_string(),
    }))
}

fn parse_entity(v: &serde_json::Value) -> Result<cedar_policy::EntityUid, PolicyError> {
    cedar_policy::EntityUid::from_json(v.clone()).map_err(|e| PolicyError::Parse(e.to_string()))
}

pub fn app(state: Arc<AppState>) -> Router {
    let cors = match std::env::var("ALLOWED_ORIGINS") {
        Ok(origins) if !origins.trim().is_empty() => {
            let mut layer = CorsLayer::new();
            for o in origins.split(',') {
                if let Ok(origin) = o.trim().parse::<http::HeaderValue>() {
                    layer = layer.allow_origin(origin);
                }
            }
            layer
        }
        _ => CorsLayer::new().allow_origin(Any),
    };

    Router::new()
        .route(
            "/health",
            get(|| async { Json(serde_json::json!({"status": "ok"})) }),
        )
        .route("/v1/authorize", post(authorize))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(authorize),
    components(schemas(AuthorizeRequest, AuthorizeResponse))
)]
pub struct ApiDoc;
