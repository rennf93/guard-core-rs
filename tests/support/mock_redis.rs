use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde_json::Value;

use guard_core_rs::error::{GuardCoreError, GuardRedisError, Result};
use guard_core_rs::protocols::redis::RedisHandlerProtocol;

pub(crate) type ScriptInvocation = (String, Vec<String>, Vec<String>);

#[derive(Default)]
pub(crate) struct MockRedis {
    pub(crate) data: DashMap<String, Value>,
    pub(crate) scripts_invoked: RwLock<Vec<ScriptInvocation>>,
    pub(crate) script_result: RwLock<Option<Value>>,
    pub(crate) fail_mode: RwLock<Option<MockRedisFailure>>,
    pub(crate) initialized: RwLock<bool>,
    pub(crate) closed: RwLock<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MockRedisFailure {
    GetKey,
    SetKey,
    Delete,
    Keys,
    Incr,
    Expire,
    RunScript,
    Initialize,
    Close,
}

impl std::fmt::Debug for MockRedis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockRedis")
            .field("size", &self.data.len())
            .finish()
    }
}

impl MockRedis {
    fn check_failure(&self, expected: MockRedisFailure) -> Result<()> {
        if let Some(mode) = *self.fail_mode.read()
            && mode == expected
        {
            return Err(GuardCoreError::Redis(GuardRedisError::new(
                503,
                "mock failure",
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl RedisHandlerProtocol for MockRedis {
    async fn initialize(&self) -> Result<()> {
        self.check_failure(MockRedisFailure::Initialize)?;
        *self.initialized.write() = true;
        Ok(())
    }

    async fn get_key(&self, namespace: &str, key: &str) -> Result<Option<Value>> {
        self.check_failure(MockRedisFailure::GetKey)?;
        let full = format!("{namespace}:{key}");
        Ok(self.data.get(&full).map(|v| v.value().clone()))
    }

    async fn set_key(
        &self,
        namespace: &str,
        key: &str,
        value: Value,
        _ttl: Option<u64>,
    ) -> Result<bool> {
        self.check_failure(MockRedisFailure::SetKey)?;
        let full = format!("{namespace}:{key}");
        self.data.insert(full, value);
        Ok(true)
    }

    async fn delete(&self, namespace: &str, key: &str) -> Result<u64> {
        self.check_failure(MockRedisFailure::Delete)?;
        let full = format!("{namespace}:{key}");
        Ok(if self.data.remove(&full).is_some() { 1 } else { 0 })
    }

    async fn keys(&self, pattern: &str) -> Result<Vec<String>> {
        self.check_failure(MockRedisFailure::Keys)?;
        let prefix = pattern.trim_end_matches('*');
        let list: Vec<String> = self
            .data
            .iter()
            .filter_map(|e| {
                if e.key().starts_with(prefix) {
                    Some(e.key().clone())
                } else {
                    None
                }
            })
            .collect();
        Ok(list)
    }

    async fn incr(&self, namespace: &str, key: &str, amount: i64) -> Result<i64> {
        self.check_failure(MockRedisFailure::Incr)?;
        let full = format!("{namespace}:{key}");
        let mut counter = self
            .data
            .get(&full)
            .and_then(|v| v.value().as_i64())
            .unwrap_or(0);
        counter += amount;
        self.data.insert(full, Value::from(counter));
        Ok(counter)
    }

    async fn expire(&self, _namespace: &str, _key: &str, _ttl: u64) -> Result<bool> {
        self.check_failure(MockRedisFailure::Expire)?;
        Ok(true)
    }

    async fn run_script(
        &self,
        script: &str,
        keys: Vec<String>,
        args: Vec<String>,
    ) -> Result<Value> {
        self.check_failure(MockRedisFailure::RunScript)?;
        self.scripts_invoked
            .write()
            .push((script.to_string(), keys, args));
        Ok(self
            .script_result
            .read()
            .clone()
            .unwrap_or(Value::Number(serde_json::Number::from(0))))
    }

    async fn close(&self) -> Result<()> {
        self.check_failure(MockRedisFailure::Close)?;
        *self.closed.write() = true;
        Ok(())
    }
}
