use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use dashmap::DashMap;
use futures::future::BoxFuture;
use parking_lot::RwLock;
use serde_json::Value;
use tokio::runtime::Runtime;

use guard_core_rs::error::Result;
use guard_core_rs::handlers::ratelimit::{CheckRateLimitArgs, CreateErrorResponseFn, RateLimitManager};
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::redis::{DynRedisHandler, RedisHandlerProtocol};
use guard_core_rs::protocols::request::{DynGuardRequest, GuardRequest, RequestState};
use guard_core_rs::protocols::response::{DynGuardResponse, GuardResponse};

struct BenchResponse {
    status: u16,
}

impl std::fmt::Debug for BenchResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BenchResponse").field("status", &self.status).finish()
    }
}

impl GuardResponse for BenchResponse {
    fn status_code(&self) -> u16 {
        self.status
    }
    fn headers(&self) -> HashMap<String, String> {
        HashMap::new()
    }
    fn set_header(&self, _name: &str, _value: &str) {}
    fn remove_header(&self, _name: &str) {}
    fn body(&self) -> Option<Bytes> {
        None
    }
}

fn error_response_fn() -> CreateErrorResponseFn {
    Arc::new(move |code: u16, _msg: String| -> BoxFuture<'static, Result<DynGuardResponse>> {
        Box::pin(async move {
            let response: DynGuardResponse = Arc::new(BenchResponse { status: code });
            Ok(response)
        })
    })
}

struct BenchRequest {
    state: Arc<RequestState>,
}

#[async_trait]
impl GuardRequest for BenchRequest {
    fn url_path(&self) -> String {
        "/api".into()
    }
    fn url_scheme(&self) -> String {
        "https".into()
    }
    fn url_full(&self) -> String {
        "https://host/api".into()
    }
    fn url_replace_scheme(&self, scheme: &str) -> String {
        format!("{scheme}://host/api")
    }
    fn method(&self) -> String {
        "GET".into()
    }
    fn client_host(&self) -> Option<String> {
        Some("10.0.0.1".into())
    }
    fn headers(&self) -> HashMap<String, String> {
        HashMap::new()
    }
    fn query_params(&self) -> HashMap<String, String> {
        HashMap::new()
    }
    async fn body(&self) -> Result<Bytes> {
        Ok(Bytes::new())
    }
    fn state(&self) -> Arc<RequestState> {
        Arc::clone(&self.state)
    }
    fn scope(&self) -> HashMap<String, Value> {
        HashMap::new()
    }
}

fn request() -> DynGuardRequest {
    Arc::new(BenchRequest { state: Arc::new(RequestState::new()) })
}

#[derive(Default)]
struct BenchRedis {
    counters: DashMap<String, i64>,
    script_result: RwLock<Option<Value>>,
}

impl std::fmt::Debug for BenchRedis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BenchRedis").finish()
    }
}

#[async_trait]
impl RedisHandlerProtocol for BenchRedis {
    async fn initialize(&self) -> Result<()> {
        Ok(())
    }
    async fn get_key(&self, _namespace: &str, _key: &str) -> Result<Option<Value>> {
        Ok(None)
    }
    async fn set_key(
        &self,
        _namespace: &str,
        _key: &str,
        _value: Value,
        _ttl: Option<u64>,
    ) -> Result<bool> {
        Ok(true)
    }
    async fn delete(&self, _namespace: &str, _key: &str) -> Result<u64> {
        Ok(0)
    }
    async fn keys(&self, _pattern: &str) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
    async fn incr(&self, _namespace: &str, _key: &str, _amount: i64) -> Result<i64> {
        Ok(1)
    }
    async fn expire(&self, _namespace: &str, _key: &str, _ttl: u64) -> Result<bool> {
        Ok(true)
    }
    async fn run_script(
        &self,
        _script: &str,
        keys: Vec<String>,
        _args: Vec<String>,
    ) -> Result<Value> {
        if let Some(v) = self.script_result.read().clone() {
            return Ok(v);
        }
        let key = keys.first().cloned().unwrap_or_default();
        let mut entry = self.counters.entry(key).or_insert(0);
        *entry += 1;
        Ok(Value::Number(serde_json::Number::from(*entry)))
    }
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

fn bench_rate_limit_in_memory(c: &mut Criterion) {
    let rt = Runtime::new().expect("runtime");
    let mut cfg = SecurityConfig::builder()
        .rate_limit(100_000)
        .rate_limit_window(60)
        .build()
        .expect("cfg");
    cfg.enable_rate_limiting = true;
    let manager = RateLimitManager::new(Arc::new(cfg));
    let create_error = error_response_fn();
    let req = request();

    c.bench_function("rate_limit_in_memory_allow", |b| {
        b.iter(|| {
            rt.block_on(async {
                let args = CheckRateLimitArgs {
                    request: &req,
                    client_ip: "10.0.0.1",
                    create_error_response: &create_error,
                    endpoint_path: "/api",
                    rate_limit: Some(100_000),
                    rate_limit_window: Some(60),
                };
                let _ = manager.check_rate_limit(black_box(args)).await;
            });
        });
    });
}

fn bench_rate_limit_redis(c: &mut Criterion) {
    let rt = Runtime::new().expect("runtime");
    let mut cfg = SecurityConfig::builder()
        .rate_limit(100_000)
        .rate_limit_window(60)
        .enable_redis(true)
        .redis_prefix("bench:")
        .build()
        .expect("cfg");
    cfg.enable_rate_limiting = true;
    let manager = RateLimitManager::new(Arc::new(cfg));
    let redis = Arc::new(BenchRedis::default());
    let dyn_redis: DynRedisHandler = Arc::clone(&redis) as Arc<dyn RedisHandlerProtocol>;
    rt.block_on(async {
        manager.initialize_redis(dyn_redis).await;
    });
    let create_error = error_response_fn();
    let req = request();

    c.bench_function("rate_limit_redis_allow", |b| {
        b.iter(|| {
            rt.block_on(async {
                let args = CheckRateLimitArgs {
                    request: &req,
                    client_ip: "10.0.0.1",
                    create_error_response: &create_error,
                    endpoint_path: "/api",
                    rate_limit: Some(100_000),
                    rate_limit_window: Some(60),
                };
                let _ = manager.check_rate_limit(black_box(args)).await;
            });
        });
    });
}

criterion_group!(rate_limit_benches, bench_rate_limit_in_memory, bench_rate_limit_redis);
criterion_main!(rate_limit_benches);
