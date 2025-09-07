use crate::{AppState, crate::shared::error::AppError};
use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use common::{ScimGroup, ScimUser, Store};
use serde::{Deserialize, Serialize};

// Note: ScimUser and ScimGroup are now in the `common` crate.
// Note: ScimStore has been removed and replaced by the generic `Store` trait in AppState.

// Note: SCIM filter parsing logic has been moved to the `scim_filter` module.

// === SCIM Bulk Operations Structures ===
// These remain as they define the API contract for bulk operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum BulkOperationMethod {
    Post,
    Put,
    Patch,
    Delete,
)

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
)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRequest {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<BulkOperation>,
    #[serde(rename = "failOnErrors", skip_serializing_if = "Option::is_none")]
    pub fail_on_errors: Option<u32>,
)

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
)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkResponse {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<BulkOperationResponse>,
)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimError {
    pub schemas: Vec<String>,
    pub detail: String,
    pub status: String,
    #[serde(rename = "scimType", skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
)

pub fn router() -> Router<AppState> {
    use crate::admin_middleware::admin_auth_middleware;
    Router::new()
        .route("/scim/v2/Users", post(create_user).get(list_users))
        .route("/scim/v2/Users/:id", get(get_user))
        .route("/scim/v2/Groups", post(create_group).get(list_groups))
        .route("/scim/v2/Groups/:id", get(get_group))
        .route_layer(axum::middleware::from_fn(admin_auth_middleware))
    // Note: Bulk operations are complex and will be refactored separately.
    // .route("/scim/v2/Bulk", post(bulk_operations))
)

// Note: scim_basic_auth middleware is removed.
// SCIM endpoints should be protected by the main admin_auth_middleware.

async fn create_user(
    State(state): State<AppState>,
    Json(user): Json<ScimUser>,
) -> Result<Json<ScimUser>, crate::shared::error::AppError> {
    let created_user = state.store.create_user(&user).await?;
    Ok(Json(created_user))
)

#[derive(Debug, Deserialize)]
struct ListParams {
    #[serde(default, rename = "startIndex")]
    start_index: Option<usize>,
    #[serde(default)]
    count: Option<usize>,
    #[serde(default)]
    filter: Option<String>,
)

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
)

// ... (filter parsing logic remains the same)

async fn list_users(
    State(state): State<AppState>,
    Query(p): Query<ListParams>,
) -> Result<Json<ListResponse<ScimUser>>, crate::shared::error::AppError> {
    let filter = p.filter.as_deref();
    let mut users = state.store.list_users(filter).await?;

    // The filtering logic that was here is now expected to be handled by the store.
    // For now, we manually sort and paginate the results from the store.
    users.sort_by(|a, b| a.id.cmp(&b.id));
    let total = users.len();
    let start = p.start_index.unwrap_or(1).saturating_sub(1);
    let count = p.count.unwrap_or(50);
    let slice = users
        .into_iter()
        .skip(start)
        .take(count)
        .collect::<Vec<_>>();

    Ok(Json(ListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: total,
        start_index: start + 1,
        items_per_page: slice.len(),
        resources: slice,
    }))
)

async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Option<ScimUser>>, crate::shared::error::AppError> {
    let user = state.store.get_user(&id).await?;
    Ok(Json(user))
)

async fn create_group(
    State(state): State<AppState>,
    Json(group): Json<ScimGroup>,
) -> Result<Json<ScimGroup>, crate::shared::error::AppError> {
    let created_group = state.store.create_group(&group).await?;
    Ok(Json(created_group))
)

// ... (filter parsing logic for groups remains the same)

async fn list_groups(
    State(state): State<AppState>,
    Query(p): Query<ListParams>,
) -> Result<Json<ListResponse<ScimGroup>>, crate::shared::error::AppError> {
    let filter = p.filter.as_deref();
    let mut groups = state.store.list_groups(filter).await?;

    groups.sort_by(|a, b| a.id.cmp(&b.id));
    let total = groups.len();
    let start = p.start_index.unwrap_or(1).saturating_sub(1);
    let count = p.count.unwrap_or(50);
    let slice = groups
        .into_iter()
        .skip(start)
        .take(count)
        .collect::<Vec<_>>();

    Ok(Json(ListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: total,
        start_index: start + 1,
        items_per_page: slice.len(),
        resources: slice,
    }))
)

async fn get_group(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Option<ScimGroup>>, crate::shared::error::AppError> {
    let group = state.store.get_group(&id).await?;
    Ok(Json(group))
)

// Note: Bulk operations implementation is removed for this refactoring pass.
// It was tightly coupled to the old ScimStore and needs a more careful redesign
// to work with the generic Store trait. This will be addressed in a future step.
// All related structs like BulkRequest, BulkResponse, etc., are kept for API compatibility.

// Constants for bulk operations
#[allow(dead_code)]
const MAX_BULK_OPERATIONS: usize = 1000;
#[allow(dead_code)]
const BULK_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
#[allow(dead_code)]
const BULK_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
#[allow(dead_code)]
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

#[allow(dead_code)]
async fn bulk_operations(
    State(state): State<AppState>,
    Json(request): Json<BulkRequest>,
) -> Result<Json<BulkResponse>, crate::shared::error::AppError> {
    // TODO: Implement transactional support for bulk operations.
    // The current implementation executes operations sequentially but does not roll back
    // on failure, which could leave the system in an inconsistent state.

    if !request.schemas.contains(&BULK_SCHEMA.to_string()) {
        return Err(crate::shared::error::AppError::InvalidRequest {
            reason: "Invalid bulk request schema".to_string(),
        });
    )
    if request.operations.len() > MAX_BULK_OPERATIONS {
        return Err(crate::shared::error::AppError::InvalidRequest {
            reason: "Too many operations".to_string(),
        });
    )

    let mut response_operations = Vec::new();
    let fail_on_errors = request.fail_on_errors.unwrap_or(0);
    let mut error_count = 0;

    for operation in &request.operations {
        let result = process_single_operation(&state, operation).await;

        match result {
            Ok(response_op) => {
                response_operations.push(response_op);
            )
            Err(error_response) => {
                error_count += 1;
                response_operations.push(error_response);
                if fail_on_errors > 0 && error_count >= fail_on_errors {
                    break;
                )
            )
        )
    )

    let response = BulkResponse {
        schemas: vec![BULK_RESPONSE_SCHEMA.to_string()],
        operations: response_operations,
    };

    Ok(Json(response))
)

#[allow(dead_code)]
async fn process_single_operation(
    state: &AppState,
    operation: &BulkOperation,
) -> Result<BulkOperationResponse, BulkOperationResponse> {
    let path_parts: Vec<&str> = operation.path.split('/').collect();
    let data = operation.data.clone().unwrap_or_default();

    match (operation.method.clone(), path_parts.as_slice()) {
        (BulkOperationMethod::Post, [_, "scim", "v2", "Users"]) => {
            create_user_operation(state, operation, data).await
        )
        (BulkOperationMethod::Put, [_, "scim", "v2", "Users", user_id]) => {
            update_user_operation(state, operation, data, user_id).await
        )
        (BulkOperationMethod::Delete, [_, "scim", "v2", "Users", user_id]) => {
            delete_user_operation(state, operation, user_id).await
        )
        (BulkOperationMethod::Post, [_, "scim", "v2", "Groups"]) => {
            create_group_operation(state, operation, data).await
        )
        (BulkOperationMethod::Patch, [_, "scim", "v2", "Users", user_id]) => {
            patch_user_operation(state, operation, data, user_id).await
        )
        _ => Err(create_error_response(
            operation.method.clone(),
            "404",
            "Operation not supported or path is invalid",
        )),
    )
)

/// Handle user creation operation
async fn create_user_operation(
    state: &AppState,
    operation: &BulkOperation,
    data: serde_json::Value,
) -> Result<BulkOperationResponse, BulkOperationResponse> {
    let user: ScimUser = serde_json::from_value(data).map_err(|_| {
        create_error_response(operation.method.clone(), "400", "Invalid user data")
    })?;
    
    let created_user = state.store.create_user(&user).await.map_err(|e| {
        create_error_response(operation.method.clone(), "500", &e.to_string())
    })?;

    Ok(create_success_response(
        BulkOperationMethod::Post,
        operation.bulk_id.clone(),
        "201",
        Some(format!("/scim/v2/Users/{}", created_user.id)),
        match serde_json::to_value(created_user) {
            Ok(v) => Some(v),
            Err(_) => None,
        },
    ))
)

/// Handle user update operation
async fn update_user_operation(
    state: &AppState,
    operation: &BulkOperation,
    data: serde_json::Value,
    user_id: &str,
) -> Result<BulkOperationResponse, BulkOperationResponse> {
    let mut user: ScimUser = serde_json::from_value(data).map_err(|_| {
        create_error_response(operation.method.clone(), "400", "Invalid user data")
    })?;
    
    user.id = user_id.to_string();
    let updated_user = state.store.update_user(&user).await.map_err(|e| {
        create_error_response(operation.method.clone(), "500", &e.to_string())
    })?;

    Ok(create_success_response(
        BulkOperationMethod::Put,
        operation.bulk_id.clone(),
        "200",
        Some(format!("/scim/v2/Users/{}", updated_user.id)),
        match serde_json::to_value(updated_user) {
            Ok(v) => Some(v),
            Err(_) => None,
        },
    ))
)

/// Handle user deletion operation
async fn delete_user_operation(
    state: &AppState,
    operation: &BulkOperation,
    user_id: &str,
) -> Result<BulkOperationResponse, BulkOperationResponse> {
    state.store.delete_user(user_id).await.map_err(|e| {
        create_error_response(operation.method.clone(), "500", &e.to_string())
    })?;

    Ok(create_success_response(
        BulkOperationMethod::Delete,
        operation.bulk_id.clone(),
        "204",
        None,
        None,
    ))
)

/// Handle group creation operation
async fn create_group_operation(
    state: &AppState,
    operation: &BulkOperation,
    data: serde_json::Value,
) -> Result<BulkOperationResponse, BulkOperationResponse> {
    let group: ScimGroup = serde_json::from_value(data).map_err(|_| {
        create_error_response(operation.method.clone(), "400", "Invalid group data")
    })?;
    
    let created_group = state.store.create_group(&group).await.map_err(|e| {
        create_error_response(operation.method.clone(), "500", &e.to_string())
    })?;

    Ok(create_success_response(
        BulkOperationMethod::Post,
        operation.bulk_id.clone(),
        "201",
        Some(format!("/scim/v2/Groups/{}", created_group.id)),
        match serde_json::to_value(created_group) {
            Ok(v) => Some(v),
            Err(_) => None,
        },
    ))
)

/// Handle user patch operation (simplified)
async fn patch_user_operation(
    state: &AppState,
    operation: &BulkOperation,
    data: serde_json::Value,
    user_id: &str,
) -> Result<BulkOperationResponse, BulkOperationResponse> {
    let patch_data: serde_json::Value = serde_json::from_value(data).map_err(|_| {
        create_error_response(operation.method.clone(), "400", "Invalid patch data")
    })?;

    let mut user = state
        .store
        .get_user(user_id)
        .await
        .map_err(|e| create_error_response(operation.method.clone(), "500", &e.to_string()))?
        .ok_or_else(|| create_error_response(operation.method.clone(), "404", "User not found"))?;

    if let Some(active) = patch_data.get("active").and_then(|v| v.as_bool()) {
        user.active = active;
    )

    let updated_user = state.store.update_user(&user).await.map_err(|e| {
        create_error_response(operation.method.clone(), "500", &e.to_string())
    })?;

    Ok(create_success_response(
        BulkOperationMethod::Patch,
        operation.bulk_id.clone(),
        "200",
        Some(format!("/scim/v2/Users/{}", updated_user.id)),
        match serde_json::to_value(updated_user) {
            Ok(v) => Some(v),
            Err(_) => None,
        },
    ))
)

/// Helper to create successful bulk operation responses
fn create_success_response(
    method: BulkOperationMethod,
    bulk_id: Option<String>,
    status: &str,
    location: Option<String>,
    response: Option<serde_json::Value>,
) -> BulkOperationResponse {
    BulkOperationResponse {
        method,
        bulk_id,
        status: status.to_string(),
        location,
        response,
        version: None,
    )
)

#[allow(dead_code)]
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
        response: serde_json::to_value(&error).ok(),
        status: status.to_string(),
    )
)
