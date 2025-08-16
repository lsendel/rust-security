use auth_service::{app, store::TokenStore, AppState};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = app(AppState {
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials: HashMap::new(),
        allowed_scopes: vec![],
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ScimUser {
    id: String,
    #[serde(rename = "userName")]
    user_name: String,
    active: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ScimGroup {
    id: String,
    #[serde(rename = "displayName")]
    display_name: String,
    members: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListResponse<T> {
    #[serde(rename = "totalResults")]
    total_results: usize,
    #[serde(rename = "startIndex")]
    start_index: usize,
    #[serde(rename = "itemsPerPage")]
    items_per_page: usize,
    #[serde(rename = "Resources")]
    resources: Vec<T>,
}

#[tokio::test]
async fn scim_users_pagination_and_filter() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // create users
    for i in 0..10 {
        let u = ScimUser { id: String::new(), user_name: format!("user{}", i), active: true };
        let res = client.post(format!("{}/scim/v2/Users", base)).json(&u).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    // page 1
    let page1: ListResponse<ScimUser> = client
        .get(format!("{}/scim/v2/Users?startIndex=1&count=3", base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page1.start_index, 1);
    assert_eq!(page1.items_per_page, 3);
    assert_eq!(page1.total_results, 10);
    assert_eq!(page1.resources.len(), 3);

    // page 2
    let page2: ListResponse<ScimUser> = client
        .get(format!("{}/scim/v2/Users?startIndex=4&count=3", base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page2.start_index, 4);
    assert_eq!(page2.items_per_page, 3);

    // filter contains
    let filtered: ListResponse<ScimUser> = client
        .get(format!("{}/scim/v2/Users?filter=userName%20co%20%22user1%22", base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(filtered.total_results >= 1);
    assert!(filtered.resources.iter().all(|u| u.user_name.contains("user1")));
}

#[tokio::test]
async fn scim_groups_pagination_and_filter() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // create groups
    for i in 0..5 {
        let g = ScimGroup { id: String::new(), display_name: format!("group{}", i), members: vec![] };
        let res = client.post(format!("{}/scim/v2/Groups", base)).json(&g).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    let filtered: ListResponse<ScimGroup> = client
        .get(format!("{}/scim/v2/Groups?filter=displayName%20co%20%22group" , base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(filtered.total_results, 5);
    assert!(filtered.resources.iter().all(|g| g.display_name.contains("group")));
}


