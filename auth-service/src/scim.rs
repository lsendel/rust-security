use axum::{extract::{Path, Query}, routing::{get, post}, Router};
use axum::extract::Extension;
use axum::{Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimUser {
    #[serde(default)]
    pub id: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimGroup {
    #[serde(default)]
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub members: Vec<String>,
}

// SCIM Filter parsing structures
#[derive(Debug, Clone, Copy, PartialEq)]
enum ScimOperator {
    Eq,  // equals
    Ne,  // not equals
    Co,  // contains
    Sw,  // starts with
    Ew,  // ends with
    Pr,  // present (has value)
    Gt,  // greater than
    Ge,  // greater than or equal
    Lt,  // less than
    Le,  // less than or equal
}

#[derive(Debug, Clone)]
struct ScimFilter {
    attribute: String,
    operator: ScimOperator,
    value: Option<String>,
}

#[derive(Error, Debug)]
enum ScimFilterError {
    #[error("Invalid filter syntax")]
    InvalidSyntax,
    #[error("Unsupported operator: {0}")]
    UnsupportedOperator(String),
    #[error("Invalid attribute: {0}")]
    InvalidAttribute(String),
    #[error("Filter too long (max 500 characters)")]
    FilterTooLong,
}

// === SCIM Bulk Operations Structures ===

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum BulkOperationMethod {
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkOperation {
    pub method: BulkOperationMethod,
    #[serde(rename = "bulkId")]
    pub bulk_id: Option<String>,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRequest {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<BulkOperation>,
    #[serde(rename = "failOnErrors", skip_serializing_if = "Option::is_none")]
    pub fail_on_errors: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkOperationResponse {
    pub method: BulkOperationMethod,
    #[serde(rename = "bulkId", skip_serializing_if = "Option::is_none")]
    pub bulk_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkResponse {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<BulkOperationResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimError {
    pub schemas: Vec<String>,
    pub detail: String,
    pub status: String,
    #[serde(rename = "scimType", skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
}

#[derive(Error, Debug)]
pub enum BulkOperationError {
    #[error("Invalid operation method: {0}")]
    InvalidMethod(String),
    #[error("Invalid path: {0}")]
    InvalidPath(String),
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),
    #[error("Invalid data for operation")]
    InvalidData,
    #[error("Bulk ID conflict: {0}")]
    BulkIdConflict(String),
    #[error("Maximum operations exceeded")]
    MaxOperationsExceeded,
    #[error("Version mismatch")]
    VersionMismatch,
    #[error("Internal processing error: {0}")]
    InternalError(String),
}

#[derive(Default)]
struct ScimStore {
    users: RwLock<HashMap<String, ScimUser>>,
    groups: RwLock<HashMap<String, ScimGroup>>,
}

pub fn router() -> Router {
    let store = std::sync::Arc::new(ScimStore::default());
    Router::new()
        .route("/scim/v2/Users", post(create_user).get(list_users))
        .route("/scim/v2/Users/:id", get(get_user))
        .route("/scim/v2/Groups", post(create_group).get(list_groups))
        .route("/scim/v2/Groups/:id", get(get_group))
        .route("/scim/v2/Bulk", post(bulk_operations))
        .layer(Extension(store))
}

async fn create_user(Extension(store): Extension<std::sync::Arc<ScimStore>>, Json(mut u): Json<ScimUser>) -> Json<ScimUser> {
    if u.id.is_empty() { u.id = uuid::Uuid::new_v4().to_string(); }
    store.users.write().await.insert(u.id.clone(), u.clone());
    Json(u)
}

#[derive(Debug, Deserialize)]
struct ListParams {
    #[serde(default, rename = "startIndex")]
    start_index: Option<usize>,
    #[serde(default)]
    count: Option<usize>,
    #[serde(default)]
    filter: Option<String>,
}

#[derive(Debug, Serialize)]
struct ListResponse<T> {
    #[serde(rename = "schemas")]
    schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    total_results: usize,
    #[serde(rename = "startIndex")]
    start_index: usize,
    #[serde(rename = "itemsPerPage")]
    items_per_page: usize,
    #[serde(rename = "Resources")]
    resources: Vec<T>,
}

fn parse_scim_filter(filter: &str) -> Result<ScimFilter, ScimFilterError> {
    // Validate filter length
    if filter.len() > crate::MAX_FILTER_LENGTH {
        return Err(ScimFilterError::FilterTooLong);
    }

    let filter = filter.trim();

    // Simple parser for SCIM filter format: "attribute op value"
    // Example: userName eq "john" or active eq true

    // Find the first space to separate attribute from the rest
    let first_space = filter.find(' ').ok_or(ScimFilterError::InvalidSyntax)?;
    let (attribute, rest) = filter.split_at(first_space);
    let rest = rest.trim();

    // Validate attribute name (alphanumeric, dots, underscores)
    if !attribute.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '_') {
        return Err(ScimFilterError::InvalidAttribute(attribute.to_string()));
    }

    // Find the operator
    let second_space = rest.find(' ');
    let (operator_str, value_str) = if let Some(idx) = second_space {
        let (op, val) = rest.split_at(idx);
        (op.trim(), Some(val.trim()))
    } else {
        // Handle operators without values (like "pr")
        (rest, None)
    };

    // Parse operator
    let operator = match operator_str.to_lowercase().as_str() {
        "eq" => ScimOperator::Eq,
        "ne" => ScimOperator::Ne,
        "co" => ScimOperator::Co,
        "sw" => ScimOperator::Sw,
        "ew" => ScimOperator::Ew,
        "pr" => ScimOperator::Pr,
        "gt" => ScimOperator::Gt,
        "ge" => ScimOperator::Ge,
        "lt" => ScimOperator::Lt,
        "le" => ScimOperator::Le,
        _ => return Err(ScimFilterError::UnsupportedOperator(operator_str.to_string())),
    };

    // Parse value (remove quotes if present)
    let value = value_str.map(|v| {
        v.trim()
            .trim_start_matches('"')
            .trim_end_matches('"')
            .to_string()
    });

    // Validate that operators requiring values have them
    if operator != ScimOperator::Pr && value.is_none() {
        return Err(ScimFilterError::InvalidSyntax);
    }

    Ok(ScimFilter {
        attribute: attribute.to_string(),
        operator,
        value,
    })
}

fn apply_filter_users(mut v: Vec<ScimUser>, filter: &str) -> Vec<ScimUser> {
    match parse_scim_filter(filter) {
        Ok(parsed) => {
            match (parsed.attribute.as_str(), parsed.operator) {
                ("userName", ScimOperator::Eq) => {
                    if let Some(val) = parsed.value {
                        v.retain(|u| u.user_name == val);
                    }
                },
                ("userName", ScimOperator::Ne) => {
                    if let Some(val) = parsed.value {
                        v.retain(|u| u.user_name != val);
                    }
                },
                ("userName", ScimOperator::Co) => {
                    if let Some(val) = parsed.value {
                        v.retain(|u| u.user_name.contains(&val));
                    }
                },
                ("userName", ScimOperator::Sw) => {
                    if let Some(val) = parsed.value {
                        v.retain(|u| u.user_name.starts_with(&val));
                    }
                },
                ("userName", ScimOperator::Ew) => {
                    if let Some(val) = parsed.value {
                        v.retain(|u| u.user_name.ends_with(&val));
                    }
                },
                ("userName", ScimOperator::Pr) => {
                    v.retain(|u| !u.user_name.is_empty());
                },
                ("active", ScimOperator::Eq) => {
                    if let Some(val) = parsed.value {
                        let bool_val = val == "true";
                        v.retain(|u| u.active == bool_val);
                    }
                },
                ("id", ScimOperator::Eq) => {
                    if let Some(val) = parsed.value {
                        v.retain(|u| u.id == val);
                    }
                },
                _ => {
                    // Unsupported filter combination, return unfiltered
                    let op = parsed.operator; // copy
                    tracing::warn!(
                        "Unsupported SCIM filter: {} {} {:?}",
                        parsed.attribute,
                        operator_str(&op),
                        parsed.value
                    );
                }
            }
        },
        Err(e) => {
            tracing::warn!("Failed to parse SCIM filter '{}': {}", filter, e);
            // Return unfiltered on parse error
        }
    }
    v
}

fn operator_str(op: &ScimOperator) -> &str {
    match op {
        ScimOperator::Eq => "eq",
        ScimOperator::Ne => "ne",
        ScimOperator::Co => "co",
        ScimOperator::Sw => "sw",
        ScimOperator::Ew => "ew",
        ScimOperator::Pr => "pr",
        ScimOperator::Gt => "gt",
        ScimOperator::Ge => "ge",
        ScimOperator::Lt => "lt",
        ScimOperator::Le => "le",
    }
}

async fn list_users(Extension(store): Extension<std::sync::Arc<ScimStore>>, Query(p): Query<ListParams>) -> Json<ListResponse<ScimUser>> {
    let mut users: Vec<ScimUser> = store.users.read().await.values().cloned().collect();
    if let Some(f) = p.filter.as_deref() { users = apply_filter_users(users, f); }
    users.sort_by(|a,b| a.id.cmp(&b.id));
    let total = users.len();
    let start = p.start_index.unwrap_or(1).saturating_sub(1);
    let count = p.count.unwrap_or(50);
    let slice = users.into_iter().skip(start).take(count).collect::<Vec<_>>();
    Json(ListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: total,
        start_index: start + 1,
        items_per_page: slice.len(),
        resources: slice,
    })
}

async fn get_user(Extension(store): Extension<std::sync::Arc<ScimStore>>, Path(id): Path<String>) -> Json<Option<ScimUser>> {
    Json(store.users.read().await.get(&id).cloned())
}

async fn create_group(Extension(store): Extension<std::sync::Arc<ScimStore>>, Json(mut g): Json<ScimGroup>) -> Json<ScimGroup> {
    if g.id.is_empty() { g.id = uuid::Uuid::new_v4().to_string(); }
    store.groups.write().await.insert(g.id.clone(), g.clone());
    Json(g)
}

fn apply_filter_groups(mut v: Vec<ScimGroup>, filter: &str) -> Vec<ScimGroup> {
    match parse_scim_filter(filter) {
        Ok(parsed) => {
            match (parsed.attribute.as_str(), parsed.operator) {
                ("displayName", ScimOperator::Eq) => {
                    if let Some(val) = parsed.value {
                        v.retain(|g| g.display_name == val);
                    }
                },
                ("displayName", ScimOperator::Ne) => {
                    if let Some(val) = parsed.value {
                        v.retain(|g| g.display_name != val);
                    }
                },
                ("displayName", ScimOperator::Co) => {
                    if let Some(val) = parsed.value {
                        v.retain(|g| g.display_name.contains(&val));
                    }
                },
                ("displayName", ScimOperator::Sw) => {
                    if let Some(val) = parsed.value {
                        v.retain(|g| g.display_name.starts_with(&val));
                    }
                },
                ("displayName", ScimOperator::Ew) => {
                    if let Some(val) = parsed.value {
                        v.retain(|g| g.display_name.ends_with(&val));
                    }
                },
                ("displayName", ScimOperator::Pr) => {
                    v.retain(|g| !g.display_name.is_empty());
                },
                ("id", ScimOperator::Eq) => {
                    if let Some(val) = parsed.value {
                        v.retain(|g| g.id == val);
                    }
                },
                _ => {
                    // Unsupported filter combination, return unfiltered
                    let op = parsed.operator; // copy
                    tracing::warn!(
                        "Unsupported SCIM group filter: {} {} {:?}",
                        parsed.attribute,
                        operator_str(&op),
                        parsed.value
                    );
                }
            }
        },
        Err(e) => {
            tracing::warn!("Failed to parse SCIM group filter '{}': {}", filter, e);
            // Return unfiltered on parse error
        }
    }
    v
}

async fn list_groups(Extension(store): Extension<std::sync::Arc<ScimStore>>, Query(p): Query<ListParams>) -> Json<ListResponse<ScimGroup>> {
    let mut groups: Vec<ScimGroup> = store.groups.read().await.values().cloned().collect();
    if let Some(f) = p.filter.as_deref() {
        groups = apply_filter_groups(groups, f);
    }
    groups.sort_by(|a,b| a.id.cmp(&b.id));
    let total = groups.len();
    let start = p.start_index.unwrap_or(1).saturating_sub(1);
    let count = p.count.unwrap_or(50);
    let slice = groups.into_iter().skip(start).take(count).collect::<Vec<_>>();
    Json(ListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: total,
        start_index: start + 1,
        items_per_page: slice.len(),
        resources: slice,
    })
}

async fn get_group(Extension(store): Extension<std::sync::Arc<ScimStore>>, Path(id): Path<String>) -> Json<Option<ScimGroup>> {
    Json(store.groups.read().await.get(&id).cloned())
}

// update/delete endpoints can be added later with proper semantics

// === SCIM Bulk Operations Implementation ===

// Constants for bulk operations
const MAX_BULK_OPERATIONS: usize = 1000;
const BULK_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
const BULK_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// SCIM Bulk Operations endpoint
/// POST /scim/v2/Bulk
///
/// Implements RFC 7644 Section 3.7 for bulk operations
/// Supports creating, updating, and deleting multiple Users and Groups in a single request
async fn bulk_operations(Extension(store): Extension<std::sync::Arc<ScimStore>>, Json(request): Json<BulkRequest>) -> Result<Json<BulkResponse>, (StatusCode, Json<ScimError>)> {
    // Validate request schemas
    if !request.schemas.contains(&BULK_SCHEMA.to_string()) {
        return Err(create_scim_error(
            StatusCode::BAD_REQUEST,
            "Invalid schema",
            Some("invalidSyntax"),
        ));
    }

    // Validate operation count
    if request.operations.len() > MAX_BULK_OPERATIONS {
        return Err(create_scim_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!("Too many operations. Maximum allowed: {}", MAX_BULK_OPERATIONS),
            Some("tooMany"),
        ));
    }

    if request.operations.is_empty() {
        return Err(create_scim_error(
            StatusCode::BAD_REQUEST,
            "No operations provided",
            Some("invalidSyntax"),
        ));
    }

    // Validate bulk IDs for uniqueness
    if let Err(error) = validate_bulk_ids(&request.operations) {
        return Err(create_scim_error(
            StatusCode::BAD_REQUEST,
            &error.to_string(),
            Some("uniqueness"),
        ));
    }

    let fail_on_errors = request.fail_on_errors.unwrap_or(0);
    let mut response_operations = Vec::new();
    let mut error_count = 0;
    let mut bulk_id_mappings: HashMap<String, String> = HashMap::new();

    // Process operations sequentially to maintain consistency
    for operation in &request.operations {
        let result = process_single_operation(&store, operation, &bulk_id_mappings).await;

        match result {
            Ok(mut response_op) => {
                // Store bulk ID mapping for future operations
                if let Some(bulk_id) = &operation.bulk_id {
                    if let Some(location) = &response_op.location {
                        if let Some(resource_id) = extract_resource_id_from_location(location) {
                            bulk_id_mappings.insert(bulk_id.clone(), resource_id);
                        }
                    }
                }
                response_op.bulk_id = operation.bulk_id.clone();
                response_operations.push(response_op);
            }
            Err(error_response) => {
                error_count += 1;
                let mut error_op = error_response;
                error_op.bulk_id = operation.bulk_id.clone();
                response_operations.push(error_op);

                // Check if we should fail on errors
                if fail_on_errors > 0 && error_count >= fail_on_errors {
                    // Log the early termination
                    tracing::warn!(
                        "Bulk operation terminated early due to {} errors (fail_on_errors={})",
                        error_count,
                        fail_on_errors
                    );
                    break;
                }
            }
        }
    }

    // Audit logging for bulk operations
    audit_bulk_operations(&request, &response_operations, error_count as usize);

    let response = BulkResponse {
        schemas: vec![BULK_RESPONSE_SCHEMA.to_string()],
        operations: response_operations,
    };

    Ok(Json(response))
}

/// Process a single bulk operation
async fn process_single_operation(
    store: &std::sync::Arc<ScimStore>,
    operation: &BulkOperation,
    bulk_id_mappings: &HashMap<String, String>,
) -> Result<BulkOperationResponse, BulkOperationResponse> {
    // Resolve bulk ID references in the path
    let resolved_path = resolve_bulk_id_references(&operation.path, bulk_id_mappings)?;

    match operation.method {
        BulkOperationMethod::Post => process_post_operation(store, &resolved_path, &operation.data).await,
        BulkOperationMethod::Put => process_put_operation(store, &resolved_path, &operation.data).await,
        BulkOperationMethod::Patch => process_patch_operation(store, &resolved_path, &operation.data).await,
        BulkOperationMethod::Delete => process_delete_operation(store, &resolved_path).await,
    }
}

/// Process POST operation (create resource)
async fn process_post_operation(
    store: &std::sync::Arc<ScimStore>,
    path: &str,
    data: &Option<serde_json::Value>,
) -> Result<BulkOperationResponse, BulkOperationResponse> {
    let data = data.as_ref().ok_or_else(|| {
        create_error_response(
            BulkOperationMethod::Post,
            "400",
            "Data required for POST operation",
        )
    })?;

    match path {
        "/Users" | "/scim/v2/Users" => {
            match serde_json::from_value::<ScimUser>(data.clone()) {
                Ok(mut user) => {
                    if user.id.is_empty() {
                        user.id = uuid::Uuid::new_v4().to_string();
                    }

                    store.users.write().await.insert(user.id.clone(), user.clone());

                    Ok(BulkOperationResponse {
                        method: BulkOperationMethod::Post,
                        bulk_id: None,
                        version: None,
                        location: Some(format!("/scim/v2/Users/{}", user.id)),
                        response: Some(serde_json::to_value(&user).unwrap()),
                        status: "201".to_string(),
                    })
                }
                Err(_) => Err(create_error_response(
                    BulkOperationMethod::Post,
                    "400",
                    "Invalid user data",
                ))
            }
        }
        "/Groups" | "/scim/v2/Groups" => {
            match serde_json::from_value::<ScimGroup>(data.clone()) {
                Ok(mut group) => {
                    if group.id.is_empty() {
                        group.id = uuid::Uuid::new_v4().to_string();
                    }

                    store.groups.write().await.insert(group.id.clone(), group.clone());

                    Ok(BulkOperationResponse {
                        method: BulkOperationMethod::Post,
                        bulk_id: None,
                        version: None,
                        location: Some(format!("/scim/v2/Groups/{}", group.id)),
                        response: Some(serde_json::to_value(&group).unwrap()),
                        status: "201".to_string(),
                    })
                }
                Err(_) => Err(create_error_response(
                    BulkOperationMethod::Post,
                    "400",
                    "Invalid group data",
                ))
            }
        }
        _ => Err(create_error_response(
            BulkOperationMethod::Post,
            "404",
            &format!("Invalid resource path: {}", path),
        ))
    }
}

/// Process PUT operation (replace resource)
async fn process_put_operation(
    store: &std::sync::Arc<ScimStore>,
    path: &str,
    data: &Option<serde_json::Value>,
) -> Result<BulkOperationResponse, BulkOperationResponse> {
    let data = data.as_ref().ok_or_else(|| {
        create_error_response(
            BulkOperationMethod::Put,
            "400",
            "Data required for PUT operation",
        )
    })?;

    let user_regex = regex::Regex::new(r"^/(?:scim/v2/)?Users/([^/]+)$").unwrap();
    let group_regex = regex::Regex::new(r"^/(?:scim/v2/)?Groups/([^/]+)$").unwrap();

    if let Some(captures) = user_regex.captures(path) {
        let user_id = captures.get(1).unwrap().as_str();

        match serde_json::from_value::<ScimUser>(data.clone()) {
            Ok(mut user) => {
                user.id = user_id.to_string();

                let mut users = store.users.write().await;
                if users.contains_key(user_id) {
                    users.insert(user_id.to_string(), user.clone());
                    Ok(BulkOperationResponse {
                        method: BulkOperationMethod::Put,
                        bulk_id: None,
                        version: None,
                        location: Some(format!("/scim/v2/Users/{}", user_id)),
                        response: Some(serde_json::to_value(&user).unwrap()),
                        status: "200".to_string(),
                    })
                } else {
                    Err(create_error_response(
                        BulkOperationMethod::Put,
                        "404",
                        &format!("User not found: {}", user_id),
                    ))
                }
            }
            Err(_) => Err(create_error_response(
                BulkOperationMethod::Put,
                "400",
                "Invalid user data",
            ))
        }
    } else if let Some(captures) = group_regex.captures(path) {
        let group_id = captures.get(1).unwrap().as_str();

        match serde_json::from_value::<ScimGroup>(data.clone()) {
            Ok(mut group) => {
                group.id = group_id.to_string();

                let mut groups = store.groups.write().await;
                if groups.contains_key(group_id) {
                    groups.insert(group_id.to_string(), group.clone());
                    Ok(BulkOperationResponse {
                        method: BulkOperationMethod::Put,
                        bulk_id: None,
                        version: None,
                        location: Some(format!("/scim/v2/Groups/{}", group_id)),
                        response: Some(serde_json::to_value(&group).unwrap()),
                        status: "200".to_string(),
                    })
                } else {
                    Err(create_error_response(
                        BulkOperationMethod::Put,
                        "404",
                        &format!("Group not found: {}", group_id),
                    ))
                }
            }
            Err(_) => Err(create_error_response(
                BulkOperationMethod::Put,
                "400",
                "Invalid group data",
            ))
        }
    } else {
        Err(create_error_response(
            BulkOperationMethod::Put,
            "404",
            &format!("Invalid resource path: {}", path),
        ))
    }
}

/// Process PATCH operation (modify resource)
async fn process_patch_operation(
    store: &std::sync::Arc<ScimStore>,
    path: &str,
    data: &Option<serde_json::Value>,
) -> Result<BulkOperationResponse, BulkOperationResponse> {
    let _data = data.as_ref().ok_or_else(|| {
        create_error_response(
            BulkOperationMethod::Patch,
            "400",
            "Data required for PATCH operation",
        )
    })?;

    let user_regex = regex::Regex::new(r"^/(?:scim/v2/)?Users/([^/]+)$").unwrap();
    let group_regex = regex::Regex::new(r"^/(?:scim/v2/)?Groups/([^/]+)$").unwrap();

    if let Some(captures) = user_regex.captures(path) {
        let user_id = captures.get(1).unwrap().as_str();

        let mut users = store.users.write().await;
        if let Some(user) = users.get_mut(user_id) {
            // Simple PATCH implementation - for a full implementation, you'd need to handle
            // SCIM PATCH operations according to RFC 7644 Section 3.5.2
            // This is a simplified version that updates specific fields

            if let Some(data_obj) = data.as_ref().and_then(|d| d.as_object()) {
                if let Some(user_name) = data_obj.get("userName").and_then(|v| v.as_str()) {
                    user.user_name = user_name.to_string();
                }
                if let Some(active) = data_obj.get("active").and_then(|v| v.as_bool()) {
                    user.active = active;
                }
            }

            Ok(BulkOperationResponse {
                method: BulkOperationMethod::Patch,
                bulk_id: None,
                version: None,
                location: Some(format!("/scim/v2/Users/{}", user_id)),
                response: Some(serde_json::to_value(user).unwrap()),
                status: "200".to_string(),
            })
        } else {
            Err(create_error_response(
                BulkOperationMethod::Patch,
                "404",
                &format!("User not found: {}", user_id),
            ))
        }
    } else if let Some(captures) = group_regex.captures(path) {
        let group_id = captures.get(1).unwrap().as_str();

        let mut groups = store.groups.write().await;
        if let Some(group) = groups.get_mut(group_id) {
            if let Some(data_obj) = data.as_ref().and_then(|d| d.as_object()) {
                if let Some(display_name) = data_obj.get("displayName").and_then(|v| v.as_str()) {
                    group.display_name = display_name.to_string();
                }
                if let Some(members) = data_obj.get("members").and_then(|v| v.as_array()) {
                    group.members = members.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                }
            }

            Ok(BulkOperationResponse {
                method: BulkOperationMethod::Patch,
                bulk_id: None,
                version: None,
                location: Some(format!("/scim/v2/Groups/{}", group_id)),
                response: Some(serde_json::to_value(group).unwrap()),
                status: "200".to_string(),
            })
        } else {
            Err(create_error_response(
                BulkOperationMethod::Patch,
                "404",
                &format!("Group not found: {}", group_id),
            ))
        }
    } else {
        Err(create_error_response(
            BulkOperationMethod::Patch,
            "404",
            &format!("Invalid resource path: {}", path),
        ))
    }
}

/// Process DELETE operation (remove resource)
async fn process_delete_operation(
    store: &std::sync::Arc<ScimStore>,
    path: &str,
) -> Result<BulkOperationResponse, BulkOperationResponse> {
    let user_regex = regex::Regex::new(r"^/(?:scim/v2/)?Users/([^/]+)$").unwrap();
    let group_regex = regex::Regex::new(r"^/(?:scim/v2/)?Groups/([^/]+)$").unwrap();

    if let Some(captures) = user_regex.captures(path) {
        let user_id = captures.get(1).unwrap().as_str();

        let mut users = store.users.write().await;
        if users.remove(user_id).is_some() {
            Ok(BulkOperationResponse {
                method: BulkOperationMethod::Delete,
                bulk_id: None,
                version: None,
                location: None,
                response: None,
                status: "204".to_string(),
            })
        } else {
            Err(create_error_response(
                BulkOperationMethod::Delete,
                "404",
                &format!("User not found: {}", user_id),
            ))
        }
    } else if let Some(captures) = group_regex.captures(path) {
        let group_id = captures.get(1).unwrap().as_str();

        let mut groups = store.groups.write().await;
        if groups.remove(group_id).is_some() {
            Ok(BulkOperationResponse {
                method: BulkOperationMethod::Delete,
                bulk_id: None,
                version: None,
                location: None,
                response: None,
                status: "204".to_string(),
            })
        } else {
            Err(create_error_response(
                BulkOperationMethod::Delete,
                "404",
                &format!("Group not found: {}", group_id),
            ))
        }
    } else {
        Err(create_error_response(
            BulkOperationMethod::Delete,
            "404",
            &format!("Invalid resource path: {}", path),
        ))
    }
}

/// Validate bulk IDs for uniqueness
fn validate_bulk_ids(operations: &[BulkOperation]) -> Result<(), BulkOperationError> {
    let mut seen_bulk_ids = std::collections::HashSet::new();

    for operation in operations {
        if let Some(bulk_id) = &operation.bulk_id {
            if !seen_bulk_ids.insert(bulk_id.clone()) {
                return Err(BulkOperationError::BulkIdConflict(bulk_id.clone()));
            }
        }
    }

    Ok(())
}

/// Resolve bulk ID references in paths
#[allow(clippy::result_large_err)]
fn resolve_bulk_id_references(
    path: &str,
    bulk_id_mappings: &HashMap<String, String>,
) -> Result<String, BulkOperationResponse> {
    let mut resolved_path = path.to_string();

    // Look for bulk ID references in the format "bulkId:some_id"
    for (bulk_id, resource_id) in bulk_id_mappings {
        let bulk_ref = format!("bulkId:{}", bulk_id);
        if resolved_path.contains(&bulk_ref) {
            resolved_path = resolved_path.replace(&bulk_ref, resource_id);
        }
    }

    Ok(resolved_path)
}

/// Extract resource ID from location URL
fn extract_resource_id_from_location(location: &str) -> Option<String> {
    if let Some(last_segment) = location.split('/').next_back() {
        if !last_segment.is_empty() {
            return Some(last_segment.to_string());
        }
    }
    None
}

/// Create a SCIM error response
fn create_scim_error(
    status: StatusCode,
    detail: &str,
    scim_type: Option<&str>,
) -> (StatusCode, Json<ScimError>) {
    let error = ScimError {
        schemas: vec![ERROR_SCHEMA.to_string()],
        detail: detail.to_string(),
        status: status.as_u16().to_string(),
        scim_type: scim_type.map(|s| s.to_string()),
    };
    (status, Json(error))
}

/// Create an error response for bulk operations
fn create_error_response(
    method: BulkOperationMethod,
    status: &str,
    detail: &str,
) -> BulkOperationResponse {
    let error = ScimError {
        schemas: vec![ERROR_SCHEMA.to_string()],
        detail: detail.to_string(),
        status: status.to_string(),
        scim_type: None,
    };

    BulkOperationResponse {
        method,
        bulk_id: None,
        version: None,
        location: None,
        response: Some(serde_json::to_value(&error).unwrap()),
        status: status.to_string(),
    }
}

/// Audit logging for bulk operations
fn audit_bulk_operations(
    request: &BulkRequest,
    responses: &[BulkOperationResponse],
    error_count: usize,
) {
    let operation_counts = request.operations.iter().fold(
        std::collections::HashMap::new(),
        |mut acc, op| {
            *acc.entry(format!("{:?}", op.method)).or_insert(0) += 1;
            acc
        }
    );

    let success_count = responses.iter().filter(|r| {
        matches!(r.status.as_str(), "200" | "201" | "204")
    }).count();

    tracing::info!(
        target: "audit",
        event = "scim_bulk_operations",
        total_operations = request.operations.len(),
        success_count = success_count,
        error_count = error_count,
        operation_counts = ?operation_counts,
        fail_on_errors = request.fail_on_errors,
    );
}


