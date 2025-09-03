use axum::{
    extract::{MatchedPath, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Registry {
    // key: concatenated labels for auth requests
    auth_counts: Mutex<HashMap<String, u64>>,
    auth_duration_sum: Mutex<f64>,
    auth_duration_count: Mutex<u64>,
    // key: context
    policies_eval: Mutex<HashMap<String, f64>>,
    // HTTP metrics
    // http_requests_total{method, path, status}
    http_counts: Mutex<HashMap<String, u64>>,
    // http_request_duration_seconds (sum & count) by method+path
    http_dur_sum: Mutex<HashMap<String, f64>>, // key: method,path
    http_dur_count: Mutex<HashMap<String, u64>>, // key: method,path
    // http_requests_in_flight by path
    http_inflight: Mutex<HashMap<String, i64>>, // key: path
    // request/response size (sum & count) by method,path
    http_req_size_sum: Mutex<HashMap<String, f64>>, // bytes
    http_req_size_count: Mutex<HashMap<String, u64>>,
    http_resp_size_sum: Mutex<HashMap<String, f64>>, // bytes
    http_resp_size_count: Mutex<HashMap<String, u64>>,
}

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| Registry {
    auth_counts: Mutex::new(HashMap::new()),
    auth_duration_sum: Mutex::new(0.0),
    auth_duration_count: Mutex::new(0),
    policies_eval: Mutex::new(HashMap::new()),
    http_counts: Mutex::new(HashMap::new()),
    http_dur_sum: Mutex::new(HashMap::new()),
    http_dur_count: Mutex::new(HashMap::new()),
    http_inflight: Mutex::new(HashMap::new()),
    http_req_size_sum: Mutex::new(HashMap::new()),
    http_req_size_count: Mutex::new(HashMap::new()),
    http_resp_size_sum: Mutex::new(HashMap::new()),
    http_resp_size_count: Mutex::new(HashMap::new()),
});

fn make_auth_key(
    decision: &str,
    principal_type: &str,
    action_type: &str,
    resource_type: &str,
    client_id: &str,
    auth_type: &str,
) -> String {
    format!(
        "decision=\"{}\",principal_type=\"{}\",action_type=\"{}\",resource_type=\"{}\",client_id=\"{}\",auth_type=\"{}\"",
        escape(decision),
        escape(principal_type),
        escape(action_type),
        escape(resource_type),
        escape(client_id),
        escape(auth_type)
    )
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"")
}

pub struct PolicyMetricsHelper;

impl PolicyMetricsHelper {
    #[allow(clippy::too_many_arguments)]
    pub fn record_authorization_request(
        decision: &str,
        principal_type: &str,
        action_type: &str,
        resource_type: &str,
        client_id: &str,
        auth_duration: Duration,
        auth_type: &str,
    ) {
        let key = make_auth_key(
            decision,
            principal_type,
            action_type,
            resource_type,
            client_id,
            auth_type,
        );
        {
            let mut counts = REGISTRY.auth_counts.lock().unwrap();
            *counts.entry(key).or_insert(0) += 1;
        }
        {
            let mut sum = REGISTRY.auth_duration_sum.lock().unwrap();
            let mut cnt = REGISTRY.auth_duration_count.lock().unwrap();
            *sum += auth_duration.as_secs_f64();
            *cnt += 1;
        }
    }

    pub fn record_policies_evaluated(context: &str, count: f64) {
        let mut map = REGISTRY.policies_eval.lock().unwrap();
        *map.entry(context.to_string()).or_insert(0.0) += count;
    }
}

pub async fn policy_metrics_middleware(req: Request, next: Next) -> Response {
    let start = Instant::now();
    // Try to capture matched path label if available
    let path_label = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unknown".to_string(), |p| p.as_str().to_string());
    // method label
    let method_label = req.method().as_str().to_string();

    // increment in-flight
    {
        let mut inflight = REGISTRY.http_inflight.lock().unwrap();
        *inflight.entry(path_label.clone()).or_insert(0) += 1;
    }

    // request size from Content-Length if present
    let req_size = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    let response = next.run(req).await;
    let elapsed = start.elapsed();

    // decrement in-flight
    {
        let mut inflight = REGISTRY.http_inflight.lock().unwrap();
        if let Some(v) = inflight.get_mut(&path_label) {
            *v -= 1;
        }
    }

    // record counters & duration
    let status_label = response.status().as_u16().to_string();
    let count_key = format!(
        "method=\"{}\",path=\"{}\",status=\"{}\"",
        escape(&method_label),
        escape(&path_label),
        status_label
    );
    {
        let mut http_counts = REGISTRY.http_counts.lock().unwrap();
        *http_counts.entry(count_key).or_insert(0) += 1;
    }
    let dur_key = format!("method=\"{}\",path=\"{}\"", escape(&method_label), escape(&path_label));
    {
        let mut sum = REGISTRY.http_dur_sum.lock().unwrap();
        let mut cnt = REGISTRY.http_dur_count.lock().unwrap();
        *sum.entry(dur_key.clone()).or_insert(0.0) += elapsed.as_secs_f64();
        *cnt.entry(dur_key).or_insert(0) += 1;
    }

    // record request size (sum/count) if known
    if req_size > 0 {
        let key = format!("method=\\\"{}\\\",path=\\\"{}\\\"", escape(&method_label), escape(&path_label));
        let mut rsum = REGISTRY.http_req_size_sum.lock().unwrap();
        let mut rcnt = REGISTRY.http_req_size_count.lock().unwrap();
        *rsum.entry(key.clone()).or_insert(0.0) += req_size as f64;
        *rcnt.entry(key).or_insert(0) += 1;
    }

    // record response size (sum/count) from Content-Length if known
    if let Some(len) = response
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        let key = format!("method=\\\"{}\\\",path=\\\"{}\\\"", escape(&method_label), escape(&path_label));
        let mut ssum = REGISTRY.http_resp_size_sum.lock().unwrap();
        let mut scnt = REGISTRY.http_resp_size_count.lock().unwrap();
        *ssum.entry(key.clone()).or_insert(0.0) += len as f64;
        *scnt.entry(key).or_insert(0) += 1;
    }

    response
}

pub async fn policy_metrics_handler() -> impl IntoResponse {
    let mut out = String::new();

    // Authorization request counter
    let counts = REGISTRY.auth_counts.lock().unwrap();
    out.push_str("# HELP authorization_requests_total Authorization requests\n");
    out.push_str("# TYPE authorization_requests_total counter\n");
    for (labels, value) in counts.iter() {
        let _ = writeln!(out, "authorization_requests_total{{{labels}}} {value}");
    }
    drop(counts);

    // Authorization duration summary (sum and count)
    let sum = *REGISTRY.auth_duration_sum.lock().unwrap();
    let cnt = *REGISTRY.auth_duration_count.lock().unwrap();
    out.push_str("# HELP authorization_duration_seconds Authorization duration\n");
    out.push_str("# TYPE authorization_duration_seconds summary\n");
    let _ = writeln!(out, "authorization_duration_seconds_sum {sum}");
    let _ = writeln!(out, "authorization_duration_seconds_count {cnt}");

    // Policies evaluated per context
    let pe = REGISTRY.policies_eval.lock().unwrap();
    out.push_str("# HELP policies_evaluated_total Policies evaluated per request\n");
    out.push_str("# TYPE policies_evaluated_total counter\n");
    for (ctx, val) in pe.iter() {
        let _ = writeln!(out, "policies_evaluated_total{{context=\"{}\"}} {val}", escape(ctx));
    }
    drop(pe);

    // HTTP metrics
    // requests total
    let http_counts = REGISTRY.http_counts.lock().unwrap();
    out.push_str("# HELP http_requests_total HTTP requests\n");
    out.push_str("# TYPE http_requests_total counter\n");
    for (labels, value) in http_counts.iter() {
        let _ = writeln!(out, "http_requests_total{{{labels}}} {value}");
    }
    drop(http_counts);

    // request duration (sum, count) by method,path
    let http_sum = REGISTRY.http_dur_sum.lock().unwrap();
    let http_cnt = REGISTRY.http_dur_count.lock().unwrap();
    out.push_str("# HELP http_request_duration_seconds HTTP request duration\n");
    out.push_str("# TYPE http_request_duration_seconds summary\n");
    for (labels, sumv) in http_sum.iter() {
        let cntv = http_cnt.get(labels).copied().unwrap_or(0);
        let _ = writeln!(out, "http_request_duration_seconds_sum{{{labels}}} {sumv}");
        let _ = writeln!(out, "http_request_duration_seconds_count{{{labels}}} {cntv}");
    }
    drop(http_cnt);
    drop(http_sum);

    // in-flight gauge
    let inflight = REGISTRY.http_inflight.lock().unwrap();
    out.push_str("# HELP http_requests_in_flight In-flight HTTP requests\n");
    out.push_str("# TYPE http_requests_in_flight gauge\n");
    for (path, val) in inflight.iter() {
        let _ = writeln!(
            out,
            "http_requests_in_flight{{path=\"{}\"}} {}",
            escape(path),
            val
        );
    }
    drop(inflight);

    // request size
    let rq_sum = REGISTRY.http_req_size_sum.lock().unwrap();
    let rq_cnt = REGISTRY.http_req_size_count.lock().unwrap();
    out.push_str("# HELP http_request_size_bytes HTTP request size\n");
    out.push_str("# TYPE http_request_size_bytes summary\n");
    for (labels, sumv) in rq_sum.iter() {
        let cntv = rq_cnt.get(labels).copied().unwrap_or(0);
        let _ = writeln!(out, "http_request_size_bytes_sum{{{labels}}} {sumv}");
        let _ = writeln!(out, "http_request_size_bytes_count{{{labels}}} {cntv}");
    }
    drop(rq_cnt);
    drop(rq_sum);

    // response size
    let rs_sum = REGISTRY.http_resp_size_sum.lock().unwrap();
    let rs_cnt = REGISTRY.http_resp_size_count.lock().unwrap();
    out.push_str("# HELP http_response_size_bytes HTTP response size\n");
    out.push_str("# TYPE http_response_size_bytes summary\n");
    for (labels, sumv) in rs_sum.iter() {
        let cntv = rs_cnt.get(labels).copied().unwrap_or(0);
        let _ = writeln!(out, "http_response_size_bytes_sum{{{labels}}} {sumv}");
        let _ = writeln!(out, "http_response_size_bytes_count{{{labels}}} {cntv}");
    }
    drop(rs_cnt);
    drop(rs_sum);

    (axum::http::StatusCode::OK, out)
}
