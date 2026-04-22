#![cfg(feature = "geoip")]
//! IPInfo-backed GeoIP handler implementing
//! [`crate::protocols::geo_ip::GeoIpHandler`].

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use maxminddb::Reader;
use serde_json::{Value, json};
use tokio::fs;
use tokio::sync::RwLock;
use tracing::error;

use crate::error::{GuardCoreError, Result};
use crate::protocols::agent::DynAgentHandler;
use crate::protocols::geo_ip::GeoIpHandler;
use crate::protocols::redis::DynRedisHandler;

/// Default download URL for the free IPInfo country+ASN database.
pub const DEFAULT_IPINFO_URL: &str = "https://ipinfo.io/data/free/country_asn.mmdb";

/// Loads the IPInfo MaxMind-compatible database and answers country lookups.
///
/// Handles download, caching, and Redis-shared distribution of the database
/// file. Implements [`crate::protocols::geo_ip::GeoIpHandler`] so it can be
/// plugged directly into the middleware.
pub struct IPInfoManager {
    token: RwLock<String>,
    db_path: RwLock<PathBuf>,
    download_url: RwLock<String>,
    reader: RwLock<Option<Arc<Reader<Vec<u8>>>>>,
    redis_handler: parking_lot::RwLock<Option<DynRedisHandler>>,
    agent_handler: parking_lot::RwLock<Option<DynAgentHandler>>,
}

impl std::fmt::Debug for IPInfoManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IPInfoManager").finish_non_exhaustive()
    }
}

impl IPInfoManager {
    /// Builds a manager that downloads from
    /// [`crate::handlers::ipinfo::DEFAULT_IPINFO_URL`] if needed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Config`] when `token` is empty.
    pub fn new(token: impl Into<String>, db_path: Option<PathBuf>) -> Result<Arc<Self>> {
        Self::new_with_url(token, db_path, DEFAULT_IPINFO_URL)
    }

    /// Builds a manager pointing at a custom download URL (mainly used in
    /// tests).
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Config`] when `token` is empty.
    pub fn new_with_url(
        token: impl Into<String>,
        db_path: Option<PathBuf>,
        download_url: impl Into<String>,
    ) -> Result<Arc<Self>> {
        let token = token.into();
        if token.is_empty() {
            return Err(GuardCoreError::Config("IPInfo token is required!".into()));
        }
        let db_path = db_path.unwrap_or_else(|| PathBuf::from("data/ipinfo/country_asn.mmdb"));
        Ok(Arc::new(Self {
            token: RwLock::new(token),
            db_path: RwLock::new(db_path),
            download_url: RwLock::new(download_url.into()),
            reader: RwLock::new(None),
            redis_handler: parking_lot::RwLock::new(None),
            agent_handler: parking_lot::RwLock::new(None),
        }))
    }

    async fn send_geo_event(
        &self,
        event_type: &str,
        ip_address: &str,
        action_taken: &str,
        reason: &str,
        metadata: serde_json::Map<String, Value>,
    ) {
        let Some(agent) = self.agent_handler.read().clone() else {
            return;
        };
        let event = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event_type": event_type,
            "ip_address": ip_address,
            "action_taken": action_taken,
            "reason": reason,
            "metadata": metadata,
        });
        if let Err(e) = agent.send_event(event).await {
            error!("Failed to send geo event to agent: {e}");
        }
    }

    async fn download_database(&self) -> Result<()> {
        let token = self.token.read().await.clone();
        let db_path = self.db_path.read().await.clone();
        let base_url = self.download_url.read().await.clone();
        let url = format!("{base_url}?token={token}");
        let retries = 3;
        let mut backoff = std::time::Duration::from_secs(1);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(GuardCoreError::Http)?;

        for attempt in 0..retries {
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let bytes = resp.bytes().await?;
                    if let Some(parent) = db_path.parent() {
                        fs::create_dir_all(parent).await?;
                    }
                    fs::write(&db_path, &bytes).await?;
                    let redis = self.redis_handler.read().clone();
                    if let Some(redis) = redis {
                        let encoded = encode_latin1(&bytes);
                        let _ = redis
                            .set_key("ipinfo", "database", Value::String(encoded), Some(86_400))
                            .await;
                    }
                    return Ok(());
                }
                Ok(resp) => {
                    if attempt == retries - 1 {
                        return Err(GuardCoreError::GeoIp(format!(
                            "GeoIP download failed: HTTP {}",
                            resp.status()
                        )));
                    }
                }
                Err(e) => {
                    if attempt == retries - 1 {
                        return Err(GuardCoreError::Http(e));
                    }
                }
            }
            tokio::time::sleep(backoff).await;
            backoff *= 2;
        }
        Err(GuardCoreError::GeoIp("GeoIP download exhausted retries".into()))
    }

    async fn is_db_outdated(&self) -> bool {
        let db_path = self.db_path.read().await.clone();
        match fs::metadata(&db_path).await {
            Ok(meta) => match meta.modified() {
                Ok(modified) => match std::time::SystemTime::now().duration_since(modified) {
                    Ok(age) => age.as_secs() > 86_400,
                    Err(_) => true,
                },
                Err(_) => true,
            },
            Err(_) => true,
        }
    }

    /// Evaluates `ip` against the supplied country allow/block lists.
    ///
    /// Returns `(is_allowed, country_code)`.
    pub async fn check_country_access(
        &self,
        ip: &str,
        blocked_countries: &[String],
        whitelist_countries: Option<&[String]>,
    ) -> (bool, Option<String>) {
        let country = self.get_country(ip);
        let Some(country) = country else {
            if whitelist_countries.is_some() {
                return (false, None);
            }
            return (true, None);
        };

        if let Some(wl) = whitelist_countries
            && !wl.contains(&country)
        {
            let mut meta = serde_json::Map::new();
            meta.insert("country".into(), json!(country.clone()));
            meta.insert("rule_type".into(), json!("country_whitelist"));
            self.send_geo_event(
                "country_blocked",
                ip,
                "request_blocked",
                &format!("Country {country} not in allowed list"),
                meta,
            )
            .await;
            return (false, Some(country));
        }

        if blocked_countries.contains(&country) {
            let mut meta = serde_json::Map::new();
            meta.insert("country".into(), json!(country.clone()));
            meta.insert("rule_type".into(), json!("country_blacklist"));
            self.send_geo_event(
                "country_blocked",
                ip,
                "request_blocked",
                &format!("Country {country} is blocked"),
                meta,
            )
            .await;
            return (false, Some(country));
        }

        (true, Some(country))
    }

    /// Drops the loaded database reader, freeing any mapped memory.
    pub async fn close(&self) {
        let mut guard = self.reader.write().await;
        *guard = None;
    }

    /// Returns a clone of the configured database path.
    pub async fn db_path(&self) -> PathBuf {
        self.db_path.read().await.clone()
    }
}

#[async_trait]
impl GeoIpHandler for IPInfoManager {
    fn is_initialized(&self) -> bool {
        self.reader.try_read().is_ok_and(|r| r.is_some())
    }

    async fn initialize(&self) -> Result<()> {
        let db_path = self.db_path.read().await.clone();
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let redis = self.redis_handler.read().clone();
        if let Some(redis) = redis
            && let Ok(Some(Value::String(cached))) = redis.get_key("ipinfo", "database").await
        {
            let bytes = decode_latin1(&cached);
            fs::write(&db_path, &bytes).await?;
            let reader = Reader::open_readfile(&db_path)
                .map_err(|e| GuardCoreError::GeoIp(format!("{e}")))?;
            *self.reader.write().await = Some(Arc::new(reader));
            return Ok(());
        }

        let should_download = !path_exists(&db_path).await || self.is_db_outdated().await;
        if should_download
            && let Err(e) = self.download_database().await
        {
            let mut meta = serde_json::Map::new();
            meta.insert("error".into(), json!(e.to_string()));
            self.send_geo_event(
                "geo_lookup_failed",
                "system",
                "database_download_failed",
                &format!("Failed to download IPInfo database: {e}"),
                meta,
            )
            .await;
            let _ = fs::remove_file(&db_path).await;
            return Ok(());
        }

        if path_exists(&db_path).await {
            let reader = Reader::open_readfile(&db_path)
                .map_err(|e| GuardCoreError::GeoIp(format!("{e}")))?;
            *self.reader.write().await = Some(Arc::new(reader));
        }
        Ok(())
    }

    async fn initialize_redis(&self, redis_handler: DynRedisHandler) -> Result<()> {
        *self.redis_handler.write() = Some(redis_handler);
        self.initialize().await
    }

    async fn initialize_agent(&self, agent_handler: DynAgentHandler) -> Result<()> {
        *self.agent_handler.write() = Some(agent_handler);
        Ok(())
    }

    fn get_country(&self, ip: &str) -> Option<String> {
        let guard = self.reader.try_read().ok()?;
        let reader = guard.as_ref()?;
        let ip_addr: std::net::IpAddr = ip.parse().ok()?;
        let lookup: Result<Value> = reader
            .lookup::<Value>(ip_addr)
            .map_err(|e| GuardCoreError::GeoIp(format!("{e}")));
        match lookup {
            Ok(value) => extract_country_code(&value),
            Err(_) => None,
        }
    }
}

async fn path_exists(path: &Path) -> bool {
    fs::metadata(path).await.is_ok()
}

fn encode_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|b| *b as char).collect()
}

fn decode_latin1(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u8).collect()
}

fn extract_country_code(value: &Value) -> Option<String> {
    if let Some(s) = value.get("country").and_then(Value::as_str) {
        return Some(s.to_string());
    }
    if let Some(code) = value
        .get("country")
        .and_then(|c| c.get("iso_code"))
        .and_then(Value::as_str)
    {
        return Some(code.to_string());
    }
    if let Some(code) = value
        .get("registered_country")
        .and_then(|c| c.get("iso_code"))
        .and_then(Value::as_str)
    {
        return Some(code.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_country_code_from_top_level_string() {
        let v = json!({"country": "US"});
        assert_eq!(extract_country_code(&v), Some("US".into()));
    }

    #[test]
    fn extract_country_code_from_nested_iso_code() {
        let v = json!({"country": {"iso_code": "GB"}});
        assert_eq!(extract_country_code(&v), Some("GB".into()));
    }

    #[test]
    fn extract_country_code_falls_back_to_registered_country() {
        let v = json!({"registered_country": {"iso_code": "DE"}});
        assert_eq!(extract_country_code(&v), Some("DE".into()));
    }

    #[test]
    fn extract_country_code_returns_none_without_data() {
        let v = json!({"continent": {"code": "EU"}});
        assert_eq!(extract_country_code(&v), None);
    }

    #[test]
    fn encode_and_decode_latin1_round_trip() {
        let bytes: Vec<u8> = (0u8..=255u8).collect();
        let encoded = encode_latin1(&bytes);
        let decoded = decode_latin1(&encoded);
        assert_eq!(decoded, bytes);
    }
}
