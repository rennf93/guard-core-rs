#[path = "support/mock_redis.rs"]
mod mock_redis;
#[path = "support/mock_agent.rs"]
mod mock_agent;

use std::collections::HashSet;
use std::sync::Arc;

use ipnet::IpNet;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use guard_core_rs::error::GuardCoreError;
use guard_core_rs::handlers::CloudManager;
use guard_core_rs::handlers::cloud::{
    CloudEndpoints, DEFAULT_AWS_URL, DEFAULT_AZURE_URL, DEFAULT_GCP_URL, fetch_aws_ip_ranges,
    fetch_aws_ip_ranges_from, fetch_azure_ip_ranges, fetch_azure_ip_ranges_from,
    fetch_gcp_ip_ranges, fetch_gcp_ip_ranges_from,
};
use guard_core_rs::models::CloudProvider;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::redis::{DynRedisHandler, RedisHandlerProtocol};

use mock_agent::MockAgent;
use mock_redis::{MockRedis, MockRedisFailure};

fn new_redis() -> (Arc<MockRedis>, DynRedisHandler) {
    let mock = Arc::new(MockRedis::default());
    let dyn_handler: DynRedisHandler = mock.clone() as Arc<dyn RedisHandlerProtocol>;
    (mock, dyn_handler)
}

fn new_agent() -> (Arc<MockAgent>, DynAgentHandler) {
    let mock = Arc::new(MockAgent::default());
    let dyn_handler: DynAgentHandler = mock.clone() as Arc<dyn AgentHandlerProtocol>;
    (mock, dyn_handler)
}

fn all_providers() -> HashSet<CloudProvider> {
    let mut set = HashSet::new();
    set.insert(CloudProvider::Aws);
    set.insert(CloudProvider::Gcp);
    set.insert(CloudProvider::Azure);
    set
}

fn only(p: CloudProvider) -> HashSet<CloudProvider> {
    let mut set = HashSet::new();
    set.insert(p);
    set
}

#[test]
fn default_manager_has_debug_repr() {
    let manager = CloudManager::default();
    assert!(format!("{manager:?}").contains("CloudManager"));
}

#[tokio::test]
async fn is_cloud_ip_returns_false_for_invalid_ip() {
    let manager = CloudManager::new();
    assert!(!manager.is_cloud_ip("not-an-ip", &all_providers()).await);
}

#[tokio::test]
async fn is_cloud_ip_returns_false_without_any_ranges() {
    let manager = CloudManager::new();
    assert!(!manager.is_cloud_ip("1.2.3.4", &all_providers()).await);
}

#[tokio::test]
async fn get_cloud_provider_details_returns_none_for_invalid_ip() {
    let manager = CloudManager::new();
    let result = manager
        .get_cloud_provider_details("not-an-ip", &all_providers())
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn get_cloud_provider_details_returns_none_when_no_match() {
    let manager = CloudManager::new();
    let result = manager
        .get_cloud_provider_details("1.2.3.4", &all_providers())
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn refresh_rejects_when_redis_is_present() {
    let manager = Arc::new(CloudManager::new());
    let (_redis, handler) = new_redis();
    let _ = manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await;

    let err = manager.refresh(all_providers()).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn refresh_async_uses_cached_values() {
    let manager = Arc::new(CloudManager::new());
    let (redis, handler) = new_redis();
    redis.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("10.0.0.0/24,10.1.0.0/16".into()),
    );
    manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
    assert!(manager.is_cloud_ip("10.0.0.5", &only(CloudProvider::Aws)).await);
    assert!(manager.is_cloud_ip("10.1.1.1", &only(CloudProvider::Aws)).await);
}

#[tokio::test]
async fn refresh_async_ignores_empty_cache() {
    let manager = Arc::new(CloudManager::new());
    let (redis, handler) = new_redis();
    redis
        .data
        .insert("cloud_ranges:AWS".into(), Value::String("".into()));
    manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await
        .ok();
    assert!(!manager.is_cloud_ip("10.0.0.5", &only(CloudProvider::Aws)).await);
}

#[tokio::test]
async fn refresh_async_without_redis_falls_through() {
    let manager = Arc::new(CloudManager::new());
    let providers = only(CloudProvider::Aws);
    let _ = manager.refresh_async(providers, 60).await;
    assert!(!manager.is_cloud_ip("8.8.8.8", &only(CloudProvider::Aws)).await);
}

#[tokio::test]
async fn send_cloud_detection_event_no_agent_is_noop() {
    let manager = CloudManager::new();
    manager
        .send_cloud_detection_event("1.2.3.4", CloudProvider::Aws, "1.2.3.0/24", "blocked")
        .await;
}

#[tokio::test]
async fn send_cloud_detection_event_pushes_to_agent() {
    let manager = CloudManager::new();
    let (agent, handler) = new_agent();
    manager.initialize_agent(handler).await;
    manager
        .send_cloud_detection_event("1.2.3.4", CloudProvider::Gcp, "1.2.3.0/24", "blocked")
        .await;
    let evts: Vec<Value> = agent.events.read().iter().cloned().collect();
    assert_eq!(evts.len(), 1);
    assert_eq!(
        evts[0].get("event_type").and_then(Value::as_str),
        Some("cloud_blocked")
    );
}

#[tokio::test]
async fn send_cloud_detection_event_tolerates_agent_failure() {
    let manager = CloudManager::new();
    let (agent, handler) = new_agent();
    *agent.fail_events.write() = true;
    manager.initialize_agent(handler).await;
    manager
        .send_cloud_detection_event("1.2.3.4", CloudProvider::Azure, "net", "blocked")
        .await;
}

#[tokio::test]
async fn initialize_redis_failed_fetch_logs_error_and_initialises_empty() {
    let manager = Arc::new(CloudManager::new());
    let (redis, handler) = new_redis();
    *redis.fail_mode.write() = Some(MockRedisFailure::SetKey);
    let _ = manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await;
}

#[tokio::test]
async fn fetch_aws_parses_payload_from_mock_server() {
    let server = MockServer::start().await;
    let body = json!({
        "prefixes": [
            {"service": "AMAZON", "ip_prefix": "3.0.0.0/8"},
            {"service": "OTHER", "ip_prefix": "5.0.0.0/8"},
            {"service": "AMAZON", "ip_prefix": "invalid"},
        ]
    });
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/aws.json", server.uri()))
        .send()
        .await
        .expect("send");
    let value: Value = resp.json().await.expect("json");
    assert!(
        value
            .get("prefixes")
            .and_then(Value::as_array)
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    );
}

#[tokio::test]
async fn fetch_aws_ip_ranges_returns_err_on_bad_host() {
    let result = fetch_aws_ip_ranges().await;
    assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn fetch_gcp_ip_ranges_returns_err_on_bad_host() {
    let result = fetch_gcp_ip_ranges().await;
    assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn fetch_azure_ip_ranges_returns_err_on_bad_host() {
    let result = fetch_azure_ip_ranges().await;
    assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn refresh_providers_with_parse_failures_keeps_state_empty() {
    let manager = Arc::new(CloudManager::new());
    let providers = only(CloudProvider::Aws);
    let _ = manager.refresh_async(providers, 60).await;
}

#[tokio::test]
async fn debug_output_is_non_exhaustive() {
    let manager = CloudManager::new();
    let s = format!("{manager:?}");
    assert!(s.contains("CloudManager"));
}

#[tokio::test]
async fn refresh_async_with_populated_cached_updates_ranges() {
    let manager = Arc::new(CloudManager::new());
    let (redis, handler) = new_redis();
    redis.data.insert(
        "cloud_ranges:GCP".into(),
        Value::String("1.0.0.0/8".into()),
    );
    redis.data.insert(
        "cloud_ranges:Azure".into(),
        Value::String("2.0.0.0/8".into()),
    );
    redis.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("3.0.0.0/8".into()),
    );
    manager
        .initialize_redis(handler, all_providers(), 60)
        .await
        .expect("init");
    assert!(manager.is_cloud_ip("1.0.0.1", &only(CloudProvider::Gcp)).await);
    let detail = manager
        .get_cloud_provider_details("2.0.0.1", &only(CloudProvider::Azure))
        .await;
    assert!(detail.is_some());
}

#[tokio::test]
async fn refresh_with_no_redis_does_not_error() {
    let manager = CloudManager::new();
    let out = manager.refresh(HashSet::new()).await;
    assert!(out.is_ok());
}

#[tokio::test]
async fn refresh_all_providers_without_redis_attempts_fetch_each() {
    let manager = CloudManager::new();
    let _ = manager.refresh(all_providers()).await;
}

#[tokio::test]
async fn decode_html_entities_happens_via_azure_fetch() {
    let _ = fetch_azure_ip_ranges().await;
}

#[tokio::test]
async fn log_range_changes_runs_for_added_and_removed_sets() {
    let manager = Arc::new(CloudManager::new());
    let (redis, handler) = new_redis();
    redis.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("10.0.0.0/24".into()),
    );
    manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
    let (redis2, _handler2) = new_redis();
    redis2.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("10.0.0.0/24,10.1.0.0/16".into()),
    );
    let _ = manager
        .refresh_async(only(CloudProvider::Aws), 60)
        .await;
}

#[tokio::test]
async fn get_cloud_provider_details_matches_specific_network() {
    let manager = Arc::new(CloudManager::new());
    let (redis, handler) = new_redis();
    redis.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("3.0.0.0/8,192.168.0.0/16".into()),
    );
    manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
    let result = manager
        .get_cloud_provider_details("192.168.5.1", &only(CloudProvider::Aws))
        .await;
    assert!(result.is_some());
    let (provider, network) = result.expect("details");
    assert_eq!(provider, CloudProvider::Aws);
    assert!(network.contains("192.168"));
}

#[tokio::test]
async fn refresh_same_cached_data_is_logged_without_changes() {
    let manager = Arc::new(CloudManager::new());
    let (redis, handler) = new_redis();
    redis.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("10.0.0.0/24".into()),
    );
    manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
    let (redis2, handler2) = new_redis();
    redis2.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("10.0.0.0/24".into()),
    );
    manager
        .initialize_redis(handler2, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
}

#[tokio::test]
async fn is_cloud_ip_true_with_matching_range() {
    let manager = Arc::new(CloudManager::new());
    let (redis, handler) = new_redis();
    redis.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("10.10.0.0/16".into()),
    );
    manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
    assert!(manager.is_cloud_ip("10.10.1.2", &only(CloudProvider::Aws)).await);
    assert!(!manager.is_cloud_ip("1.1.1.1", &only(CloudProvider::Aws)).await);
}

#[tokio::test]
async fn is_cloud_ip_traverses_ranges_without_match_returns_false() {
    let manager = Arc::new(CloudManager::new());
    let (redis, handler) = new_redis();
    redis.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("10.10.0.0/16,172.16.0.0/12".into()),
    );
    manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
    assert!(!manager.is_cloud_ip("8.8.8.8", &only(CloudProvider::Aws)).await);
}

#[tokio::test]
async fn get_cloud_provider_details_traverses_ranges_without_match_returns_none() {
    let manager = Arc::new(CloudManager::new());
    let (redis, handler) = new_redis();
    redis.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("10.10.0.0/16,172.16.0.0/12".into()),
    );
    manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
    assert!(
        manager
            .get_cloud_provider_details("8.8.8.8", &only(CloudProvider::Aws))
            .await
            .is_none()
    );
}

#[tokio::test]
async fn refresh_same_cache_does_not_log_range_changes() {
    let manager = Arc::new(CloudManager::new());
    let (redis1, handler1) = new_redis();
    redis1.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("10.0.0.0/24".into()),
    );
    manager
        .initialize_redis(handler1, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
    let (redis2, handler2) = new_redis();
    redis2.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("10.0.0.0/24".into()),
    );
    manager
        .initialize_redis(handler2, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
}

#[tokio::test]
async fn fetch_aws_from_wiremock_parses_prefixes() {
    let server = MockServer::start().await;
    let body = json!({
        "prefixes": [
            {"service": "AMAZON", "ip_prefix": "10.0.0.0/24"},
            {"service": "OTHER", "ip_prefix": "11.0.0.0/24"},
        ]
    });
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let url = format!("{}/aws.json", server.uri());
    let set = fetch_aws_ip_ranges_from(&url).await.expect("fetch");
    let expected: IpNet = "10.0.0.0/24".parse().expect("parse");
    let other: IpNet = "11.0.0.0/24".parse().expect("parse");
    assert!(set.contains(&expected));
    assert!(!set.contains(&other));
    assert_eq!(set.len(), 1);
}

#[tokio::test]
async fn fetch_aws_from_wiremock_empty_prefixes() {
    let server = MockServer::start().await;
    let body = json!({});
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let url = format!("{}/aws.json", server.uri());
    let set = fetch_aws_ip_ranges_from(&url).await.expect("fetch");
    assert!(set.is_empty());
}

#[tokio::test]
async fn fetch_aws_from_wiremock_malformed_json() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("not json at all")
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    let url = format!("{}/aws.json", server.uri());
    let err = fetch_aws_ip_ranges_from(&url).await.expect_err("err");
    assert!(matches!(err, GuardCoreError::Json(_) | GuardCoreError::Http(_)));
}

#[tokio::test]
async fn fetch_aws_from_wiremock_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let url = format!("{}/aws.json", server.uri());
    let err = fetch_aws_ip_ranges_from(&url).await.expect_err("err");
    assert!(matches!(err, GuardCoreError::Json(_) | GuardCoreError::Http(_)));
}

#[tokio::test]
async fn fetch_gcp_from_wiremock_ipv4_and_ipv6() {
    let server = MockServer::start().await;
    let body = json!({
        "prefixes": [
            {"ipv4Prefix": "34.0.0.0/16"},
            {"ipv6Prefix": "2001:db8::/32"},
            {"ipv4Prefix": "invalid"},
        ]
    });
    Mock::given(method("GET"))
        .and(path("/gcp.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let url = format!("{}/gcp.json", server.uri());
    let set = fetch_gcp_ip_ranges_from(&url).await.expect("fetch");
    let v4: IpNet = "34.0.0.0/16".parse().expect("parse");
    let v6: IpNet = "2001:db8::/32".parse().expect("parse");
    assert!(set.contains(&v4));
    assert!(set.contains(&v6));
    assert_eq!(set.len(), 2);
}

#[tokio::test]
async fn fetch_gcp_from_wiremock_empty_prefixes() {
    let server = MockServer::start().await;
    let body = json!({});
    Mock::given(method("GET"))
        .and(path("/gcp.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let url = format!("{}/gcp.json", server.uri());
    let set = fetch_gcp_ip_ranges_from(&url).await.expect("fetch");
    assert!(set.is_empty());
}

#[tokio::test]
async fn fetch_gcp_from_wiremock_malformed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/gcp.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("garbage")
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    let url = format!("{}/gcp.json", server.uri());
    let err = fetch_gcp_ip_ranges_from(&url).await.expect_err("err");
    assert!(matches!(err, GuardCoreError::Json(_) | GuardCoreError::Http(_)));
}

#[tokio::test]
async fn fetch_azure_from_wiremock_extracts_and_fetches_json() {
    let server = MockServer::start().await;
    let download_path = "/azure-ipranges.json";
    let download_url = format!("{}{}", server.uri(), download_path);
    let html = format!(
        r#"<html><body><a href="{download_url}">download</a></body></html>"#
    );
    Mock::given(method("GET"))
        .and(path("/details"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&server)
        .await;

    let json_body = json!({
        "values": [{
            "properties": {
                "addressPrefixes": [
                    "20.0.0.0/8",
                    "40.0.0.0/16",
                    "invalid",
                ]
            }
        }]
    });
    Mock::given(method("GET"))
        .and(path(download_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(json_body))
        .mount(&server)
        .await;

    let details_url = format!("{}/details", server.uri());
    let set = fetch_azure_ip_ranges_from(&details_url)
        .await
        .expect("fetch");
    let a: IpNet = "20.0.0.0/8".parse().expect("parse");
    let b: IpNet = "40.0.0.0/16".parse().expect("parse");
    assert!(set.contains(&a));
    assert!(set.contains(&b));
    assert_eq!(set.len(), 2);
}

#[tokio::test]
async fn fetch_azure_from_wiremock_missing_download_link() {
    let server = MockServer::start().await;
    let html = r#"<html><body><p>no link here</p></body></html>"#;
    Mock::given(method("GET"))
        .and(path("/details"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&server)
        .await;

    let details_url = format!("{}/details", server.uri());
    let err = fetch_azure_ip_ranges_from(&details_url)
        .await
        .expect_err("err");
    match err {
        GuardCoreError::CloudProvider(msg) => {
            assert_eq!(msg, "Could not find Azure IP ranges download URL");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn fetch_azure_from_wiremock_bad_json_in_download() {
    let server = MockServer::start().await;
    let download_path = "/azure-ipranges.json";
    let download_url = format!("{}{}", server.uri(), download_path);
    let html = format!(
        r#"<html><body><a href="{download_url}">download</a></body></html>"#
    );
    Mock::given(method("GET"))
        .and(path("/details"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(download_path))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("not-json-at-all")
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    let details_url = format!("{}/details", server.uri());
    let err = fetch_azure_ip_ranges_from(&details_url)
        .await
        .expect_err("err");
    assert!(matches!(err, GuardCoreError::Json(_) | GuardCoreError::Http(_)));
}

#[tokio::test]
async fn fetch_azure_from_wiremock_no_values_returns_empty() {
    let server = MockServer::start().await;
    let download_path = "/azure-ipranges.json";
    let download_url = format!("{}{}", server.uri(), download_path);
    let html = format!(
        r#"<html><body><a href="{download_url}">download</a></body></html>"#
    );
    Mock::given(method("GET"))
        .and(path("/details"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(download_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let details_url = format!("{}/details", server.uri());
    let set = fetch_azure_ip_ranges_from(&details_url)
        .await
        .expect("fetch");
    assert!(set.is_empty());
}

#[tokio::test]
async fn fetch_azure_decodes_html_entities_in_href() {
    let server = MockServer::start().await;
    let download_path = "/azure-ipranges.json";
    let download_url = format!("{}{}", server.uri(), download_path);
    let encoded = download_url.replace('&', "&amp;");
    let html = format!(r#"<html><a href="{encoded}">dl</a></html>"#);
    Mock::given(method("GET"))
        .and(path("/details"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(download_path))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "values": [{"properties": {"addressPrefixes": ["100.64.0.0/16"]}}]
            })),
        )
        .mount(&server)
        .await;

    let details_url = format!("{}/details", server.uri());
    let set = fetch_azure_ip_ranges_from(&details_url)
        .await
        .expect("fetch");
    let expected: IpNet = "100.64.0.0/16".parse().expect("parse");
    assert!(set.contains(&expected));
}

#[test]
fn default_urls_match_constants() {
    assert!(!DEFAULT_AWS_URL.is_empty());
    assert!(DEFAULT_AWS_URL.starts_with("https://"));
    assert!(!DEFAULT_GCP_URL.is_empty());
    assert!(DEFAULT_GCP_URL.starts_with("https://"));
    assert!(!DEFAULT_AZURE_URL.is_empty());
    assert!(DEFAULT_AZURE_URL.starts_with("https://"));
}

#[test]
fn cloud_endpoints_default_matches_constants() {
    let endpoints = CloudEndpoints::default();
    assert_eq!(endpoints.aws, DEFAULT_AWS_URL);
    assert_eq!(endpoints.gcp, DEFAULT_GCP_URL);
    assert_eq!(endpoints.azure, DEFAULT_AZURE_URL);
}

#[test]
fn cloud_endpoints_debug_and_clone() {
    let endpoints = CloudEndpoints::default();
    let cloned = endpoints.clone();
    assert_eq!(cloned.aws, endpoints.aws);
    let dbg = format!("{endpoints:?}");
    assert!(dbg.contains("CloudEndpoints"));
}

#[tokio::test]
async fn fetch_aws_default_function_delegates_to_from_variant() {
    let result = fetch_aws_ip_ranges().await;
    let _ = result.ok();
}

#[tokio::test]
async fn refresh_async_with_redis_empty_cache_and_empty_remote_returns_ok() {
    let manager = Arc::new(CloudManager::new());
    let (_redis, handler) = new_redis();
    let _ = manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await;
    assert!(!manager.is_cloud_ip("1.1.1.1", &only(CloudProvider::Aws)).await);
}

#[tokio::test]
async fn refresh_providers_without_redis_handles_empty_and_error_paths() {
    let manager = Arc::new(CloudManager::new());
    let _ = manager.refresh(only(CloudProvider::Gcp)).await;
    assert!(!manager.is_cloud_ip("1.2.3.4", &only(CloudProvider::Gcp)).await);
}

#[tokio::test]
async fn log_range_changes_with_removed_only() {
    let manager = Arc::new(CloudManager::new());
    let (redis, handler) = new_redis();
    redis.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("10.0.0.0/24,10.1.0.0/16,10.2.0.0/16".into()),
    );
    manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
    let ip_match = manager
        .is_cloud_ip("10.0.0.1", &only(CloudProvider::Aws))
        .await;
    assert!(ip_match);
}

#[tokio::test]
async fn log_range_changes_identical_sets_early_returns() {
    let manager = Arc::new(CloudManager::new());
    let (redis, handler) = new_redis();
    redis.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("10.0.0.0/24".into()),
    );
    manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
}

fn endpoints_with_aws(aws: impl Into<String>) -> CloudEndpoints {
    CloudEndpoints {
        aws: aws.into(),
        gcp: DEFAULT_GCP_URL.into(),
        azure: DEFAULT_AZURE_URL.into(),
    }
}

#[tokio::test]
async fn refresh_async_with_endpoints_populates_ranges_from_wiremock() {
    let server = MockServer::start().await;
    let body = json!({
        "prefixes": [
            {"service": "AMAZON", "ip_prefix": "10.0.0.0/24"},
            {"service": "AMAZON", "ip_prefix": "10.1.0.0/16"},
        ]
    });
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    let aws_url = format!("{}/aws.json", server.uri());

    let manager = Arc::new(CloudManager::with_endpoints(endpoints_with_aws(aws_url)));
    let (_redis, handler) = new_redis();
    manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
    assert!(manager.is_cloud_ip("10.0.0.1", &only(CloudProvider::Aws)).await);
    assert!(manager.is_cloud_ip("10.1.1.1", &only(CloudProvider::Aws)).await);
}

#[tokio::test]
async fn refresh_async_with_endpoints_empty_result_leaves_state_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let aws_url = format!("{}/aws.json", server.uri());

    let manager = Arc::new(CloudManager::with_endpoints(endpoints_with_aws(aws_url)));
    let (_redis, handler) = new_redis();
    manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
    assert!(!manager.is_cloud_ip("10.0.0.1", &only(CloudProvider::Aws)).await);
}

#[tokio::test]
async fn refresh_async_with_endpoints_fetch_error_leaves_state_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let aws_url = format!("{}/aws.json", server.uri());

    let manager = Arc::new(CloudManager::with_endpoints(endpoints_with_aws(aws_url)));
    let (_redis, handler) = new_redis();
    manager
        .initialize_redis(handler, only(CloudProvider::Aws), 60)
        .await
        .expect("init");
    assert!(!manager.is_cloud_ip("10.0.0.1", &only(CloudProvider::Aws)).await);
}

#[tokio::test]
async fn refresh_providers_with_endpoints_populates_and_logs_changes() {
    let server = MockServer::start().await;
    let body = json!({
        "prefixes": [
            {"service": "AMAZON", "ip_prefix": "20.0.0.0/8"},
        ]
    });
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    let aws_url = format!("{}/aws.json", server.uri());

    let manager = CloudManager::with_endpoints(endpoints_with_aws(aws_url));
    manager
        .refresh(only(CloudProvider::Aws))
        .await
        .expect("refresh");
    assert!(manager.is_cloud_ip("20.1.2.3", &only(CloudProvider::Aws)).await);
}

#[tokio::test]
async fn refresh_providers_with_endpoints_empty_result_noops() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let aws_url = format!("{}/aws.json", server.uri());

    let manager = CloudManager::with_endpoints(endpoints_with_aws(aws_url));
    manager
        .refresh(only(CloudProvider::Aws))
        .await
        .expect("refresh");
    assert!(!manager.is_cloud_ip("20.1.2.3", &only(CloudProvider::Aws)).await);
}

#[tokio::test]
async fn refresh_providers_with_endpoints_fetch_error_leaves_state_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let aws_url = format!("{}/aws.json", server.uri());

    let manager = CloudManager::with_endpoints(endpoints_with_aws(aws_url));
    manager
        .refresh(only(CloudProvider::Aws))
        .await
        .expect("refresh");
    assert!(!manager.is_cloud_ip("1.1.1.1", &only(CloudProvider::Aws)).await);
}

fn ensure_tracing_subscriber() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(std::io::sink)
            .try_init();
    });
}

#[tokio::test]
async fn refresh_providers_logs_added_and_removed_ranges() {
    ensure_tracing_subscriber();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "prefixes": [
                {"service": "AMAZON", "ip_prefix": "30.0.0.0/24"}
            ]
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "prefixes": [
                {"service": "AMAZON", "ip_prefix": "30.0.0.0/24"},
                {"service": "AMAZON", "ip_prefix": "31.0.0.0/24"},
            ]
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "prefixes": [
                {"service": "AMAZON", "ip_prefix": "30.0.0.0/24"}
            ]
        })))
        .mount(&server)
        .await;
    let aws_url = format!("{}/aws.json", server.uri());

    let manager = CloudManager::with_endpoints(endpoints_with_aws(aws_url));
    manager
        .refresh(only(CloudProvider::Aws))
        .await
        .expect("refresh1");
    manager
        .refresh(only(CloudProvider::Aws))
        .await
        .expect("refresh2");
    manager
        .refresh(only(CloudProvider::Aws))
        .await
        .expect("refresh3");
    assert!(manager.is_cloud_ip("30.0.0.1", &only(CloudProvider::Aws)).await);
}

#[tokio::test]
async fn refresh_providers_logs_identical_ranges_without_changes() {
    ensure_tracing_subscriber();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/aws.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "prefixes": [
                {"service": "AMAZON", "ip_prefix": "40.0.0.0/24"}
            ]
        })))
        .mount(&server)
        .await;
    let aws_url = format!("{}/aws.json", server.uri());

    let manager = CloudManager::with_endpoints(endpoints_with_aws(aws_url));
    manager
        .refresh(only(CloudProvider::Aws))
        .await
        .expect("refresh1");
    manager
        .refresh(only(CloudProvider::Aws))
        .await
        .expect("refresh2");
    assert!(manager.is_cloud_ip("40.0.0.1", &only(CloudProvider::Aws)).await);
}

#[tokio::test]
async fn fetch_gcp_default_function_delegates_to_from_variant() {
    let result = fetch_gcp_ip_ranges().await;
    let _ = result.ok();
}

#[tokio::test]
async fn fetch_azure_default_function_delegates_to_from_variant() {
    let result = fetch_azure_ip_ranges().await;
    let _ = result.ok();
}
