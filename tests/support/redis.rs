use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use serde_json::Value;

use guard_core_rs::error::Result;
use guard_core_rs::protocols::redis::{DynRedisHandler, RedisHandlerProtocol};

#[derive(Default)]
pub(crate) struct MockRedisHandler {
    pub(crate) store: RwLock<HashMap<String, Value>>,
    pub(crate) init_calls: RwLock<u32>,
    pub(crate) close_calls: RwLock<u32>,
}

impl std::fmt::Debug for MockRedisHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockRedisHandler")
            .field("entries", &self.store.read().len())
            .finish()
    }
}

impl MockRedisHandler {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(crate) fn dyn_handler(self: Arc<Self>) -> DynRedisHandler {
        self
    }

    pub(crate) fn init_calls(&self) -> u32 {
        *self.init_calls.read()
    }
}

fn key_for(namespace: &str, key: &str) -> String {
    format!("{namespace}:{key}")
}

#[async_trait]
impl RedisHandlerProtocol for MockRedisHandler {
    async fn get_key(&self, namespace: &str, key: &str) -> Result<Option<Value>> {
        Ok(self.store.read().get(&key_for(namespace, key)).cloned())
    }

    async fn set_key(
        &self,
        namespace: &str,
        key: &str,
        value: Value,
        _ttl: Option<u64>,
    ) -> Result<bool> {
        self.store.write().insert(key_for(namespace, key), value);
        Ok(true)
    }

    async fn delete(&self, namespace: &str, key: &str) -> Result<u64> {
        let removed = self.store.write().remove(&key_for(namespace, key));
        Ok(if removed.is_some() { 1 } else { 0 })
    }

    async fn keys(&self, pattern: &str) -> Result<Vec<String>> {
        let prefix = pattern.trim_end_matches('*');
        Ok(self
            .store
            .read()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }

    async fn initialize(&self) -> Result<()> {
        *self.init_calls.write() += 1;
        Ok(())
    }

    async fn incr(&self, namespace: &str, key: &str, amount: i64) -> Result<i64> {
        let full_key = key_for(namespace, key);
        let mut store = self.store.write();
        let new_value = match store.get(&full_key).and_then(Value::as_i64) {
            Some(existing) => existing + amount,
            None => amount,
        };
        store.insert(full_key, Value::Number(new_value.into()));
        Ok(new_value)
    }

    async fn expire(&self, _namespace: &str, _key: &str, _ttl: u64) -> Result<bool> {
        Ok(true)
    }

    async fn run_script(
        &self,
        _script: &str,
        _keys: Vec<String>,
        _args: Vec<String>,
    ) -> Result<Value> {
        Ok(Value::Null)
    }

    async fn close(&self) -> Result<()> {
        *self.close_calls.write() += 1;
        Ok(())
    }
}
