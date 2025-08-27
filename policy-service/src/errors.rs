
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Policy not found: {id}")]
    PolicyNotFound { id: String },

    #[error("Policy validation failed: {reason}")]
    PolicyValidationFailed { reason: String },

    #[error("Policy compilation failed")]
    PolicyCompilationFailed {
        #[source]
        source: cedar_policy::ParseErrors,
    },

    #[error("Policy evaluation failed: {context}")]
    PolicyEvaluationFailed { context: String },
}

#[derive(Error, Debug)]
pub enum EntityError {
    #[error("Entity not found: {entity_type}:{entity_id}")]
    EntityNotFound {
        entity_type: String,
        entity_id: String,
    },

    #[error("Entity validation failed: {reason}")]
    EntityValidationFailed { reason: String },

    #[error("Entity parsing failed")]
    EntityParsingFailed {
        #[from]
        source: cedar_policy::EntityAttrEvaluationError,
    },
}

#[derive(Error, Debug)]
pub enum AuthorizationError {
    #[error("Authorization request failed: {reason}")]
    RequestFailed { reason: String },

    #[error("Invalid principal: {details}")]
    InvalidPrincipal { details: String },

    #[error("Invalid action: {action}")]
    InvalidAction { action: String },

    #[error("Invalid resource: {details}")]
    InvalidResource { details: String },

    #[error("Context parsing failed: {reason}")]
    InvalidContext { reason: String },
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration loading failed: {reason}")]
    LoadFailed { reason: String },

    #[error("Missing required configuration: {key}")]
    MissingRequired { key: String },

    #[error("Invalid configuration value for {key}: {reason}")]
    InvalidValue { key: String, reason: String },
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error(transparent)]
    Policy(#[from] PolicyError),

    #[error(transparent)]
    Entity(#[from] EntityError),

    #[error(transparent)]
    Authorization(#[from] AuthorizationError),

    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error("I/O error: {context}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON processing error")]
    Json {
        #[from]
        source: serde_json::Error,
    },

    #[error("Internal server error: {context}")]
    Internal { context: String },

    #[error("Service unavailable: {reason}")]
    ServiceUnavailable { reason: String },

    #[error("Rate limit exceeded for {client_id}")]
    RateLimitExceeded { client_id: String },

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Policy not found")]
    PolicyNotFound,

    #[error("Internal server error")]
    InternalServerError,
}

impl AppError {
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    pub fn internal(context: impl Into<String>) -> Self {
        Self::Internal {
            context: context.into(),
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            AppError::Policy(PolicyError::PolicyNotFound { .. }) => StatusCode::NOT_FOUND,
            AppError::Entity(EntityError::EntityNotFound { .. }) => StatusCode::NOT_FOUND,
            AppError::PolicyNotFound => StatusCode::NOT_FOUND,
            
            AppError::Policy(_) 
            | AppError::Entity(_) 
            | AppError::Authorization(_) 
            | AppError::InvalidInput(_) => StatusCode::BAD_REQUEST,
            
            AppError::RateLimitExceeded { .. } => StatusCode::TOO_MANY_REQUESTS,
            
            AppError::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            
            AppError::Config(_) 
            | AppError::Io { .. }
            | AppError::Json { .. }
            | AppError::Internal { .. }
            | AppError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn error_type(&self) -> &'static str {
        match self {
            AppError::Policy(_) => "policy_error",
            AppError::Entity(_) => "entity_error",
            AppError::Authorization(_) => "authorization_error",
            AppError::Config(_) => "configuration_error",
            AppError::Io { .. } => "io_error",
            AppError::Json { .. } => "json_error",
            AppError::Internal { .. } | AppError::InternalServerError => "internal_error",
            AppError::ServiceUnavailable { .. } => "service_unavailable",
            AppError::RateLimitExceeded { .. } => "rate_limit_exceeded",
            AppError::InvalidInput(_) => "invalid_input",
            AppError::PolicyNotFound => "policy_not_found",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_type = self.error_type();
        let error_message = self.to_string();

        let body = Json(json!({
            "error": {
                "type": error_type,
                "message": error_message,
                "status": status.as_u16(),
            }
        }));

        (status, body).into_response()
    }
}

// Type alias for convenience (uncomment when needed)
// pub type Result<T> = std::result::Result<T, AppError>;
