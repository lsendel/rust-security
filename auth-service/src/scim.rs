use axum::{extract::{Path, Query}, routing::{get, post}, Router};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use once_cell::sync::Lazy;
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimUser {
    pub id: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimGroup {
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

static USERS: Lazy<RwLock<HashMap<String, ScimUser>>> = Lazy::new(|| RwLock::new(HashMap::new()));
static GROUPS: Lazy<RwLock<HashMap<String, ScimGroup>>> = Lazy::new(|| RwLock::new(HashMap::new()));

pub fn router() -> Router {
    Router::new()
        .route("/scim/v2/Users", post(create_user).get(list_users))
        .route("/scim/v2/Users/:id", get(get_user))
        .route("/scim/v2/Groups", post(create_group).get(list_groups))
        .route("/scim/v2/Groups/:id", get(get_group))
}

async fn create_user(Json(mut u): Json<ScimUser>) -> Json<ScimUser> {
    if u.id.is_empty() { u.id = uuid::Uuid::new_v4().to_string(); }
    USERS.write().await.insert(u.id.clone(), u.clone());
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

async fn list_users(Query(p): Query<ListParams>) -> Json<ListResponse<ScimUser>> {
    let mut users: Vec<ScimUser> = USERS.read().await.values().cloned().collect();
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

async fn get_user(Path(id): Path<String>) -> Json<Option<ScimUser>> {
    Json(USERS.read().await.get(&id).cloned())
}

async fn create_group(Json(mut g): Json<ScimGroup>) -> Json<ScimGroup> {
    if g.id.is_empty() { g.id = uuid::Uuid::new_v4().to_string(); }
    GROUPS.write().await.insert(g.id.clone(), g.clone());
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

async fn list_groups(Query(p): Query<ListParams>) -> Json<ListResponse<ScimGroup>> {
    let mut groups: Vec<ScimGroup> = GROUPS.read().await.values().cloned().collect();
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

async fn get_group(Path(id): Path<String>) -> Json<Option<ScimGroup>> {
    Json(GROUPS.read().await.get(&id).cloned())
}

// update/delete endpoints can be added later with proper semantics


