use axum::{extract::Path, routing::{get, post}, Router};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use once_cell::sync::Lazy;

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

async fn list_users() -> Json<Vec<ScimUser>> {
    Json(USERS.read().await.values().cloned().collect())
}

async fn get_user(Path(id): Path<String>) -> Json<Option<ScimUser>> {
    Json(USERS.read().await.get(&id).cloned())
}

async fn create_group(Json(mut g): Json<ScimGroup>) -> Json<ScimGroup> {
    if g.id.is_empty() { g.id = uuid::Uuid::new_v4().to_string(); }
    GROUPS.write().await.insert(g.id.clone(), g.clone());
    Json(g)
}

async fn list_groups() -> Json<Vec<ScimGroup>> {
    Json(GROUPS.read().await.values().cloned().collect())
}

async fn get_group(Path(id): Path<String>) -> Json<Option<ScimGroup>> {
    Json(GROUPS.read().await.get(&id).cloned())
}

// update/delete endpoints can be added later with proper semantics


