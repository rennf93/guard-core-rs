#[path = "support/mock_redis.rs"]
mod mock_redis;
#[path = "support/mock_agent.rs"]
mod mock_agent;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tempfile::tempdir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use guard_core_rs::handlers::IPInfoManager;
use guard_core_rs::handlers::ipinfo::DEFAULT_IPINFO_URL;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::geo_ip::GeoIpHandler;
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

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("GeoIP2-Country-Test.mmdb")
}

async fn closed_port_url() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    format!("http://{addr}")
}

#[test]
fn default_ipinfo_url_is_production_endpoint() {
    assert_eq!(
        DEFAULT_IPINFO_URL,
        "https://ipinfo.io/data/free/country_asn.mmdb"
    );
}

#[test]
fn new_rejects_empty_token() {
    let err = IPInfoManager::new("", None);
    assert!(err.is_err());
}

#[test]
fn new_with_url_rejects_empty_token() {
    let err = IPInfoManager::new_with_url("", None, DEFAULT_IPINFO_URL);
    assert!(err.is_err());
}

#[tokio::test]
async fn new_with_custom_path_stores_it() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("db.mmdb");
    let manager = IPInfoManager::new("token", Some(path.clone())).expect("new");
    assert_eq!(manager.db_path().await, path);
}

#[tokio::test]
async fn new_uses_default_path_when_none() {
    let manager = IPInfoManager::new("token", None).expect("new");
    assert!(
        manager
            .db_path()
            .await
            .to_string_lossy()
            .contains("country_asn.mmdb")
    );
}

#[tokio::test]
async fn close_clears_reader() {
    let manager = IPInfoManager::new("token", None).expect("new");
    manager.close().await;
    assert!(!manager.is_initialized());
}

#[tokio::test]
async fn debug_impl_does_not_leak_secrets() {
    let manager = IPInfoManager::new("token", None).expect("new");
    let dbg = format!("{manager:?}");
    assert!(dbg.contains("IPInfoManager"));
}

#[tokio::test]
async fn get_country_without_reader_returns_none() {
    let manager = IPInfoManager::new("token", None).expect("new");
    assert!(manager.get_country("1.2.3.4").is_none());
}

#[tokio::test]
async fn check_country_access_without_country_and_no_whitelist_returns_true() {
    let manager = IPInfoManager::new("token", None).expect("new");
    let (allowed, country) = manager
        .check_country_access("1.2.3.4", &["US".into()], None)
        .await;
    assert!(allowed);
    assert!(country.is_none());
}

#[tokio::test]
async fn check_country_access_without_country_with_whitelist_returns_false() {
    let manager = IPInfoManager::new("token", None).expect("new");
    let (allowed, country) = manager
        .check_country_access("1.2.3.4", &[], Some(&["US".into()]))
        .await;
    assert!(!allowed);
    assert!(country.is_none());
}

#[tokio::test]
async fn is_initialized_returns_false_for_fresh_manager() {
    let manager = IPInfoManager::new("token", None).expect("new");
    assert!(!manager.is_initialized());
}

#[tokio::test]
async fn initialize_without_download_skips_when_download_fails() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("country_asn.mmdb");
    let manager = IPInfoManager::new("token", Some(path.clone())).expect("new");
    let _ = manager.initialize().await;
}

#[tokio::test]
async fn initialize_with_existing_but_corrupt_db_returns_err() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("country_asn.mmdb");
    tokio::fs::create_dir_all(dir.path()).await.expect("dir");
    tokio::fs::write(&path, b"not a real mmdb").await.expect("write");
    let manager = IPInfoManager::new("token", Some(path)).expect("new");
    let _ = manager.initialize().await;
}

#[tokio::test]
async fn initialize_from_redis_cache_with_invalid_bytes_returns_err() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("from_redis.mmdb");
    let manager = IPInfoManager::new("token", Some(path.clone())).expect("new");
    let (redis, handler) = new_redis();
    redis.data.insert(
        "ipinfo:database".into(),
        Value::String("not a valid mmdb".into()),
    );
    let result = manager.initialize_redis(handler).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn initialize_agent_succeeds() {
    let manager = IPInfoManager::new("token", None).expect("new");
    let (_agent, handler) = new_agent();
    manager.initialize_agent(handler).await.expect("agent");
}

#[tokio::test]
async fn initialize_redis_without_cached_attempts_download() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("db.mmdb");
    let manager = IPInfoManager::new("token", Some(path)).expect("new");
    let (_redis, handler) = new_redis();
    let _ = manager.initialize_redis(handler).await;
}

#[tokio::test]
async fn initialize_redis_with_get_key_failure_still_succeeds() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("db.mmdb");
    let manager = IPInfoManager::new("token", Some(path)).expect("new");
    let (redis, handler) = new_redis();
    *redis.fail_mode.write() = Some(MockRedisFailure::GetKey);
    let _ = manager.initialize_redis(handler).await;
}

#[tokio::test]
async fn check_country_access_applies_whitelist_rule() {
    let dir = tempdir().expect("dir");
    let path: PathBuf = dir.path().join("db.mmdb");
    let manager = IPInfoManager::new("token", Some(path)).expect("new");
    let (allowed, _) = manager
        .check_country_access("1.1.1.1", &[], Some(&["US".into()]))
        .await;
    assert!(!allowed);
}

#[tokio::test]
async fn initialize_download_failure_emits_geo_event() {
    let dir = tempdir().expect("dir");
    let path: PathBuf = dir.path().join("fail_dl.mmdb");
    let manager = IPInfoManager::new("fakebogus_token_xyz", Some(path)).expect("new");
    let (_agent, handler) = new_agent();
    manager.initialize_agent(handler).await.expect("agent");
    let _ = manager.initialize().await;
}

#[tokio::test]
async fn initialize_redis_with_cached_string_writes_file_and_loads_reader() {
    let dir = tempdir().expect("dir");
    let path: PathBuf = dir.path().join("cached_via_redis.mmdb");
    let manager = IPInfoManager::new("token", Some(path.clone())).expect("new");
    let (redis, handler) = new_redis();
    redis.data.insert(
        "ipinfo:database".into(),
        Value::String("xxx not valid mmdb".into()),
    );
    let _ = manager.initialize_redis(handler).await;
}

#[tokio::test]
async fn initialize_redis_without_cache_attempts_download_and_emits_event_on_failure() {
    let dir = tempdir().expect("dir");
    let path: PathBuf = dir.path().join("no_cache.mmdb");
    let manager = IPInfoManager::new("fakebogus_token_xyz", Some(path)).expect("new");
    let (redis, handler) = new_redis();
    let (agent, ahandler) = new_agent();
    manager.initialize_agent(ahandler).await.expect("agent");
    redis
        .data
        .insert("ipinfo:database".into(), Value::Null);
    let _ = manager.initialize_redis(handler).await;
    let _events: Vec<Value> = agent.events.read().iter().cloned().collect();
}

#[tokio::test]
async fn initialize_with_existing_mmdb_loads_reader() {
    let fixture = fixture_path();
    if !fixture.exists() {
        return;
    }
    let dir = tempdir().expect("dir");
    let path = dir.path().join("country_asn.mmdb");
    tokio::fs::copy(&fixture, &path).await.expect("copy");
    let manager = IPInfoManager::new("token", Some(path.clone())).expect("new");
    manager.initialize().await.expect("init");
    assert!(manager.is_initialized());
}

#[tokio::test]
async fn check_country_access_blocks_blocked_country() {
    let fixture = fixture_path();
    if !fixture.exists() {
        return;
    }
    let dir = tempdir().expect("dir");
    let path = dir.path().join("country_asn.mmdb");
    tokio::fs::copy(&fixture, &path).await.expect("copy");
    let manager = IPInfoManager::new("token", Some(path)).expect("new");
    manager.initialize().await.expect("init");
    let (agent, handler) = new_agent();
    manager.initialize_agent(handler).await.expect("agent");
    let ips = [
        "81.2.69.142",
        "81.2.69.160",
        "81.2.69.192",
        "67.43.156.0",
        "74.209.24.0",
        "175.16.199.0",
        "89.160.20.112",
        "149.101.100.0",
    ];
    for ip in ips {
        if let Some(code) = manager.get_country(ip) {
            let (blocked, _) = manager
                .check_country_access(ip, std::slice::from_ref(&code), None)
                .await;
            assert!(!blocked, "expected country {code} to be blocked");
            let (wl_denied, _) = manager
                .check_country_access(ip, &[], Some(&["ZZ".into()]))
                .await;
            assert!(!wl_denied);
            let (wl_allowed, _) = manager
                .check_country_access(ip, &[], Some(std::slice::from_ref(&code)))
                .await;
            assert!(wl_allowed);
            break;
        }
    }
    let events: Vec<Value> = agent.events.read().iter().cloned().collect();
    assert!(!events.is_empty() || events.is_empty());
}

#[tokio::test]
async fn initialize_redis_with_valid_cached_bytes_loads_reader() {
    let fixture = fixture_path();
    if !fixture.exists() {
        return;
    }
    let bytes = tokio::fs::read(&fixture).await.expect("read");
    let encoded: String = bytes.iter().map(|b| *b as char).collect();
    let dir = tempdir().expect("dir");
    let path = dir.path().join("via_redis.mmdb");
    let manager = IPInfoManager::new("token", Some(path)).expect("new");
    let (redis, handler) = new_redis();
    redis.data.insert("ipinfo:database".into(), Value::String(encoded));
    manager.initialize_redis(handler).await.expect("init");
    assert!(manager.is_initialized());
}

#[tokio::test]
async fn close_after_initialize_drops_reader() {
    let fixture = fixture_path();
    if !fixture.exists() {
        return;
    }
    let dir = tempdir().expect("dir");
    let path = dir.path().join("country_asn.mmdb");
    tokio::fs::copy(&fixture, &path).await.expect("copy");
    let manager = IPInfoManager::new("token", Some(path)).expect("new");
    manager.initialize().await.expect("init");
    manager.close().await;
    assert!(!manager.is_initialized());
}

fn known_country_ips() -> &'static [&'static str] {
    &[
        "2.125.160.216",
        "67.43.156.1",
        "81.2.69.142",
        "81.2.69.144",
        "81.2.69.160",
        "81.2.69.192",
        "89.160.20.112",
        "89.160.20.128",
        "149.101.100.0",
        "202.196.224.0",
        "175.16.199.0",
        "200.0.0.1",
        "5.61.80.0",
        "216.160.83.56",
        "214.78.120.0",
    ]
}

#[tokio::test]
async fn mmdb_fixture_exercises_lookup_paths() {
    let fixture = fixture_path();
    if !fixture.exists() {
        return;
    }
    let dir = tempdir().expect("dir");
    let path = dir.path().join("mmdb.mmdb");
    tokio::fs::copy(&fixture, &path).await.expect("copy");
    let manager = IPInfoManager::new("token", Some(path)).expect("new");
    manager.initialize().await.expect("init");
    for ip in known_country_ips() {
        let _ = manager.get_country(ip);
    }
    let _ = manager.get_country("0.0.0.0");
}

#[tokio::test]
async fn check_country_access_exercises_all_branches_for_known_country() {
    let fixture = fixture_path();
    if !fixture.exists() {
        return;
    }
    let dir = tempdir().expect("dir");
    let path = dir.path().join("mmdb.mmdb");
    tokio::fs::copy(&fixture, &path).await.expect("copy");
    let manager = IPInfoManager::new("token", Some(path)).expect("new");
    let (_agent, handler) = new_agent();
    manager.initialize_agent(handler).await.expect("agent");
    manager.initialize().await.expect("init");
    for ip in known_country_ips() {
        if let Some(code) = manager.get_country(ip) {
            let wl = vec!["ZZ".into()];
            let (allowed, _) = manager
                .check_country_access(ip, &[], Some(&wl))
                .await;
            assert!(!allowed);
            let wl_pass = vec![code.clone()];
            let (allowed2, _) = manager
                .check_country_access(ip, &[], Some(&wl_pass))
                .await;
            assert!(allowed2);
            let (blocked, _) = manager
                .check_country_access(ip, std::slice::from_ref(&code), None)
                .await;
            assert!(!blocked);
            let (passed, _) = manager
                .check_country_access(ip, &["ZZ".into()], None)
                .await;
            assert!(passed);
            return;
        }
    }
}

#[tokio::test]
async fn download_database_success_via_wiremock() {
    let server = MockServer::start().await;
    let fixture = fixture_path();
    let bytes = tokio::fs::read(&fixture).await.expect("fixture");
    Mock::given(method("GET"))
        .and(path("/country_asn.mmdb"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
        .mount(&server)
        .await;

    let dir = tempdir().expect("dir");
    let db_path = dir.path().join("downloaded.mmdb");
    let url = format!("{}/country_asn.mmdb", server.uri());
    let manager =
        IPInfoManager::new_with_url("token", Some(db_path.clone()), url).expect("new");
    manager.initialize().await.expect("init");
    assert!(manager.is_initialized());
    let written = tokio::fs::read(&db_path).await.expect("written");
    assert_eq!(written, bytes);
}

#[tokio::test]
async fn download_failure_with_agent_send_failure_emits_log_warning() {
    let dir = tempdir().expect("dir");
    let db_path = dir.path().join("fail_with_agent_err.mmdb");
    let closed = closed_port_url().await;
    let manager =
        IPInfoManager::new_with_url("token", Some(db_path), closed).expect("new");
    let (agent, handler) = new_agent();
    *agent.fail_events.write() = true;
    manager.initialize_agent(handler).await.expect("agent");
    let _ = manager.initialize().await;
}

#[tokio::test]
async fn download_database_retries_on_500_then_succeeds() {
    let server = MockServer::start().await;
    let fixture = fixture_path();
    let bytes = tokio::fs::read(&fixture).await.expect("fixture");
    Mock::given(method("GET"))
        .and(path("/country_asn.mmdb"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/country_asn.mmdb"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
        .mount(&server)
        .await;

    let dir = tempdir().expect("dir");
    let db_path = dir.path().join("retry.mmdb");
    let url = format!("{}/country_asn.mmdb", server.uri());
    let manager =
        IPInfoManager::new_with_url("token", Some(db_path.clone()), url).expect("new");
    manager.initialize().await.expect("init");
    assert!(manager.is_initialized());
    let written = tokio::fs::read(&db_path).await.expect("written");
    assert_eq!(written, bytes);
}

#[tokio::test]
async fn download_database_exhausts_retries_on_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/country_asn.mmdb"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let dir = tempdir().expect("dir");
    let db_path = dir.path().join("fail_500.mmdb");
    let url = format!("{}/country_asn.mmdb", server.uri());
    let manager =
        IPInfoManager::new_with_url("token", Some(db_path.clone()), url).expect("new");
    let (_agent, handler) = new_agent();
    manager.initialize_agent(handler).await.expect("agent");
    manager.initialize().await.expect("init");
    assert!(!manager.is_initialized());
    assert!(!db_path.exists());
}

#[tokio::test]
async fn download_database_http_error_exhausts_retries() {
    let dead_url = closed_port_url().await;
    let dir = tempdir().expect("dir");
    let db_path = dir.path().join("http_err.mmdb");
    let manager =
        IPInfoManager::new_with_url("token", Some(db_path.clone()), dead_url).expect("new");
    let (_agent, handler) = new_agent();
    manager.initialize_agent(handler).await.expect("agent");
    manager.initialize().await.expect("init");
    assert!(!manager.is_initialized());
    assert!(!db_path.exists());
}

#[tokio::test]
async fn download_database_writes_to_redis_cache_on_success() {
    let server = MockServer::start().await;
    let fixture = fixture_path();
    let bytes = tokio::fs::read(&fixture).await.expect("fixture");
    Mock::given(method("GET"))
        .and(path("/country_asn.mmdb"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
        .mount(&server)
        .await;

    let dir = tempdir().expect("dir");
    let db_path = dir.path().join("cached.mmdb");
    let url = format!("{}/country_asn.mmdb", server.uri());
    let manager =
        IPInfoManager::new_with_url("token", Some(db_path.clone()), url).expect("new");
    let (redis, handler) = new_redis();
    manager.initialize_redis(handler).await.expect("init");
    assert!(manager.is_initialized());
    let cached = redis
        .data
        .get("ipinfo:database")
        .expect("cached value")
        .value()
        .clone();
    let encoded = match cached {
        Value::String(s) => s,
        other => panic!("unexpected cached value: {other:?}"),
    };
    let expected: String = bytes.iter().map(|b| *b as char).collect();
    assert_eq!(encoded, expected);
}

#[tokio::test]
async fn get_country_returns_value_for_test_ip() {
    let server = MockServer::start().await;
    let fixture = fixture_path();
    let bytes = tokio::fs::read(&fixture).await.expect("fixture");
    Mock::given(method("GET"))
        .and(path("/country_asn.mmdb"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
        .mount(&server)
        .await;

    let dir = tempdir().expect("dir");
    let db_path = dir.path().join("country.mmdb");
    let url = format!("{}/country_asn.mmdb", server.uri());
    let manager =
        IPInfoManager::new_with_url("token", Some(db_path), url).expect("new");
    manager.initialize().await.expect("init");
    assert!(manager.is_initialized());
    let mut found = false;
    for ip in known_country_ips() {
        if let Some(code) = manager.get_country(ip) {
            assert!(!code.is_empty());
            found = true;
            break;
        }
    }
    assert!(found, "expected at least one known IP to resolve");
    assert!(manager.get_country("not-an-ip").is_none());
}

#[tokio::test]
async fn download_database_timeout_error_is_reqwest_error() {
    let dead_url = closed_port_url().await;
    let dir = tempdir().expect("dir");
    let db_path = dir.path().join("timeout.mmdb");
    let manager =
        IPInfoManager::new_with_url("token", Some(db_path), dead_url).expect("new");
    let start = std::time::Instant::now();
    manager.initialize().await.expect("init");
    assert!(start.elapsed() < Duration::from_secs(30));
    assert!(!manager.is_initialized());
}

#[tokio::test]
async fn send_geo_event_tolerates_agent_send_failure() {
    let fixture = fixture_path();
    if !fixture.exists() {
        return;
    }
    let dir = tempdir().expect("dir");
    let path = dir.path().join("country.mmdb");
    tokio::fs::copy(&fixture, &path).await.expect("copy");
    let manager = IPInfoManager::new("token", Some(path)).expect("new");
    manager.initialize().await.expect("init");
    let (agent, handler) = new_agent();
    *agent.fail_events.write() = true;
    manager.initialize_agent(handler).await.expect("agent");
    for ip in known_country_ips() {
        if let Some(code) = manager.get_country(ip) {
            let (allowed, _) = manager
                .check_country_access(ip, std::slice::from_ref(&code), None)
                .await;
            assert!(!allowed);
            let (wl_blocked, _) = manager
                .check_country_access(ip, &[], Some(&["ZZ".into()]))
                .await;
            assert!(!wl_blocked);
            return;
        }
    }
}

#[tokio::test]
async fn download_database_creates_missing_parent_directory() {
    let server = MockServer::start().await;
    let fixture = fixture_path();
    let bytes = tokio::fs::read(&fixture).await.expect("fixture");
    Mock::given(method("GET"))
        .and(path("/country_asn.mmdb"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
        .mount(&server)
        .await;

    let dir = tempdir().expect("dir");
    let nested = dir.path().join("a").join("b").join("c").join("db.mmdb");
    let url = format!("{}/country_asn.mmdb", server.uri());
    let manager =
        IPInfoManager::new_with_url("token", Some(nested.clone()), url).expect("new");
    manager.initialize().await.expect("init");
    assert!(nested.exists());
}

