#![cfg(feature = "cloud-providers")]
//! Cloud provider IP-range refresh and lookup manager.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use regex::Regex;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::{error, info};

use crate::error::{GuardCoreError, Result};
use crate::models::CloudProvider;
use crate::protocols::agent::DynAgentHandler;
use crate::protocols::redis::DynRedisHandler;

/// Default URL for AWS IP ranges (`ip-ranges.json`).
pub const DEFAULT_AWS_URL: &str = "https://ip-ranges.amazonaws.com/ip-ranges.json";
/// Default URL for GCP IP ranges (`cloud.json`).
pub const DEFAULT_GCP_URL: &str = "https://www.gstatic.com/ipranges/cloud.json";
/// Default Azure download page URL from which the actual JSON URL is scraped.
pub const DEFAULT_AZURE_URL: &str =
    "https://www.microsoft.com/en-us/download/details.aspx?id=56519";

/// Tuple of per-provider fetch URLs used by
/// [`crate::handlers::cloud::CloudManager::with_endpoints`].
#[derive(Clone, Debug)]
pub struct CloudEndpoints {
    /// URL serving the AWS IP ranges JSON.
    pub aws: String,
    /// URL serving the GCP IP ranges JSON.
    pub gcp: String,
    /// URL of the Azure download page containing the actual JSON link.
    pub azure: String,
}

impl Default for CloudEndpoints {
    fn default() -> Self {
        Self {
            aws: DEFAULT_AWS_URL.into(),
            gcp: DEFAULT_GCP_URL.into(),
            azure: DEFAULT_AZURE_URL.into(),
        }
    }
}

/// Fetches, caches, and queries the public IP ranges published by the AWS,
/// GCP, and Azure cloud providers.
///
/// # Examples
///
/// ```no_run
/// use std::collections::HashSet;
/// use guard_core_rs::handlers::cloud::CloudManager;
/// use guard_core_rs::models::CloudProvider;
///
/// # async fn run() {
/// let manager = CloudManager::new();
/// let providers: HashSet<CloudProvider> = [CloudProvider::Aws].into_iter().collect();
/// assert!(!manager.is_cloud_ip("127.0.0.1", &providers).await);
/// # }
/// ```
pub struct CloudManager {
    ip_ranges: RwLock<HashMap<CloudProvider, HashSet<IpNet>>>,
    last_updated: RwLock<HashMap<CloudProvider, Option<DateTime<Utc>>>>,
    redis_handler: parking_lot::RwLock<Option<DynRedisHandler>>,
    agent_handler: parking_lot::RwLock<Option<DynAgentHandler>>,
    endpoints: CloudEndpoints,
}

impl std::fmt::Debug for CloudManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudManager").finish_non_exhaustive()
    }
}

impl Default for CloudManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudManager {
    /// Creates a manager that uses the default upstream URLs.
    pub fn new() -> Self {
        Self::with_endpoints(CloudEndpoints::default())
    }

    /// Creates a manager with the supplied per-provider endpoints.
    pub fn with_endpoints(endpoints: CloudEndpoints) -> Self {
        let all = [CloudProvider::Aws, CloudProvider::Gcp, CloudProvider::Azure];
        let ranges = all.iter().map(|p| (*p, HashSet::new())).collect();
        let last = all.iter().map(|p| (*p, None)).collect();
        Self {
            ip_ranges: RwLock::new(ranges),
            last_updated: RwLock::new(last),
            redis_handler: parking_lot::RwLock::new(None),
            agent_handler: parking_lot::RwLock::new(None),
            endpoints,
        }
    }

    /// Installs the Redis handler and performs an initial cache-aware
    /// refresh of the supplied providers.
    ///
    /// # Errors
    ///
    /// Returns any error propagated by
    /// [`crate::handlers::cloud::CloudManager::refresh_async`].
    pub async fn initialize_redis(
        self: &Arc<Self>,
        redis: DynRedisHandler,
        providers: HashSet<CloudProvider>,
        ttl: u64,
    ) -> Result<()> {
        *self.redis_handler.write() = Some(redis);
        self.refresh_async(providers, ttl).await
    }

    /// Installs the Guard Agent handler used to emit refresh events.
    pub async fn initialize_agent(&self, agent: DynAgentHandler) {
        *self.agent_handler.write() = Some(agent);
    }

    /// Refreshes the cached IP ranges for every provider in `providers`.
    ///
    /// Use [`crate::handlers::cloud::CloudManager::refresh_async`] when a
    /// Redis handler is attached.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::CloudProvider`] when Redis
    /// is configured; otherwise fetch errors are logged but not propagated.
    pub async fn refresh(&self, providers: HashSet<CloudProvider>) -> Result<()> {
        if self.redis_handler.read().is_some() {
            return Err(GuardCoreError::CloudProvider(
                "Use refresh_async() when Redis is enabled".into(),
            ));
        }
        self.refresh_providers(&providers).await;
        Ok(())
    }

    /// Cache-aware variant of
    /// [`crate::handlers::cloud::CloudManager::refresh`] that reads and
    /// writes ranges through Redis when available.
    ///
    /// # Errors
    ///
    /// Fetch errors are logged; the method only returns `Err` if the Redis
    /// handler surfaces one.
    pub async fn refresh_async(
        &self,
        providers: HashSet<CloudProvider>,
        ttl: u64,
    ) -> Result<()> {
        let redis = self.redis_handler.read().clone();
        let Some(redis) = redis else {
            self.refresh_providers(&providers).await;
            return Ok(());
        };

        for provider in &providers {
            let cached = redis
                .get_key("cloud_ranges", provider.as_str())
                .await
                .ok()
                .flatten();
            if let Some(Value::String(cached_str)) = cached {
                let parsed: HashSet<IpNet> = cached_str
                    .split(',')
                    .filter_map(|s| s.trim().parse::<IpNet>().ok())
                    .collect();
                if !parsed.is_empty() {
                    self.ip_ranges.write().await.insert(*provider, parsed);
                    continue;
                }
            }

            match self.fetch_provider(*provider).await {
                Ok(ranges) if !ranges.is_empty() => {
                    let mut write = self.ip_ranges.write().await;
                    let old = write.get(provider).cloned().unwrap_or_default();
                    log_range_changes(*provider, &old, &ranges);
                    write.insert(*provider, ranges.clone());
                    drop(write);
                    self.last_updated
                        .write()
                        .await
                        .insert(*provider, Some(Utc::now()));
                    let serialized = ranges
                        .iter()
                        .map(IpNet::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                    let _ = redis
                        .set_key(
                            "cloud_ranges",
                            provider.as_str(),
                            Value::String(serialized),
                            Some(ttl),
                        )
                        .await;
                }
                Ok(_) => {}
                Err(e) => {
                    error!("Failed to refresh {} IP ranges: {}", provider.as_str(), e);
                    let mut write = self.ip_ranges.write().await;
                    write.entry(*provider).or_insert_with(HashSet::new);
                }
            }
        }
        Ok(())
    }

    async fn refresh_providers(&self, providers: &HashSet<CloudProvider>) {
        for provider in providers {
            match self.fetch_provider(*provider).await {
                Ok(ranges) if !ranges.is_empty() => {
                    let mut write = self.ip_ranges.write().await;
                    let old = write.get(provider).cloned().unwrap_or_default();
                    log_range_changes(*provider, &old, &ranges);
                    write.insert(*provider, ranges);
                    drop(write);
                    self.last_updated
                        .write()
                        .await
                        .insert(*provider, Some(Utc::now()));
                }
                Ok(_) => {}
                Err(e) => {
                    error!("Failed to fetch {} IP ranges: {}", provider.as_str(), e);
                    self.ip_ranges.write().await.insert(*provider, HashSet::new());
                }
            }
        }
    }

    /// Returns `true` when `ip` belongs to any of the supplied `providers`.
    pub async fn is_cloud_ip(&self, ip: &str, providers: &HashSet<CloudProvider>) -> bool {
        let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() else {
            error!("Invalid IP address: {ip}");
            return false;
        };
        let ranges = self.ip_ranges.read().await;
        for provider in providers {
            if let Some(networks) = ranges.get(provider) {
                for net in networks {
                    if net.contains(&ip_addr) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Returns the matching provider and CIDR for `ip`, or [`None`] when the
    /// IP does not belong to any listed provider.
    pub async fn get_cloud_provider_details(
        &self,
        ip: &str,
        providers: &HashSet<CloudProvider>,
    ) -> Option<(CloudProvider, String)> {
        let ip_addr: std::net::IpAddr = ip.parse().ok()?;
        let ranges = self.ip_ranges.read().await;
        for provider in providers {
            if let Some(networks) = ranges.get(provider) {
                for net in networks {
                    if net.contains(&ip_addr) {
                        return Some((*provider, net.to_string()));
                    }
                }
            }
        }
        None
    }

    /// Emits a `cloud_blocked` agent event describing `ip`/`provider`.
    pub async fn send_cloud_detection_event(
        &self,
        ip: &str,
        provider: CloudProvider,
        network: &str,
        action_taken: &str,
    ) {
        let Some(agent) = self.agent_handler.read().clone() else {
            return;
        };
        let event = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "event_type": "cloud_blocked",
            "ip_address": ip,
            "action_taken": action_taken,
            "reason": format!("IP belongs to blocked cloud provider: {}", provider.as_str()),
            "metadata": {
                "cloud_provider": provider.as_str(),
                "network": network,
            },
        });
        if let Err(e) = agent.send_event(event).await {
            error!("Failed to send cloud event to agent: {e}");
        }
    }

    async fn fetch_provider(&self, provider: CloudProvider) -> Result<HashSet<IpNet>> {
        match provider {
            CloudProvider::Aws => fetch_aws_ip_ranges_from(&self.endpoints.aws).await,
            CloudProvider::Gcp => fetch_gcp_ip_ranges_from(&self.endpoints.gcp).await,
            CloudProvider::Azure => fetch_azure_ip_ranges_from(&self.endpoints.azure).await,
        }
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Fetches the AWS IP ranges from the default endpoint.
///
/// # Errors
///
/// Returns [`crate::error::GuardCoreError::Http`] or
/// [`crate::error::GuardCoreError::Json`] on transport failures.
pub async fn fetch_aws_ip_ranges() -> Result<HashSet<IpNet>> {
    fetch_aws_ip_ranges_from(DEFAULT_AWS_URL).await
}

/// Fetches the AWS IP ranges from the supplied URL.
///
/// # Errors
///
/// Returns [`crate::error::GuardCoreError::Http`] or
/// [`crate::error::GuardCoreError::Json`] on transport failures.
pub async fn fetch_aws_ip_ranges_from(url: &str) -> Result<HashSet<IpNet>> {
    let client = client();
    let resp = client.get(url).send().await?;
    let value: Value = resp.json().await?;
    let Some(prefixes) = value.get("prefixes").and_then(Value::as_array) else {
        return Ok(HashSet::new());
    };
    let mut out = HashSet::new();
    for pref in prefixes {
        if pref.get("service").and_then(Value::as_str) == Some("AMAZON")
            && let Some(ip_prefix) = pref.get("ip_prefix").and_then(Value::as_str)
                && let Ok(net) = ip_prefix.parse::<IpNet>()
            {
                out.insert(net);
            }
    }
    Ok(out)
}

/// Fetches the GCP IP ranges from the default endpoint.
///
/// # Errors
///
/// Returns [`crate::error::GuardCoreError::Http`] or
/// [`crate::error::GuardCoreError::Json`] on transport failures.
pub async fn fetch_gcp_ip_ranges() -> Result<HashSet<IpNet>> {
    fetch_gcp_ip_ranges_from(DEFAULT_GCP_URL).await
}

/// Fetches the GCP IP ranges from the supplied URL.
///
/// # Errors
///
/// Returns [`crate::error::GuardCoreError::Http`] or
/// [`crate::error::GuardCoreError::Json`] on transport failures.
pub async fn fetch_gcp_ip_ranges_from(url: &str) -> Result<HashSet<IpNet>> {
    let client = client();
    let resp = client.get(url).send().await?;
    let value: Value = resp.json().await?;
    let Some(prefixes) = value.get("prefixes").and_then(Value::as_array) else {
        return Ok(HashSet::new());
    };
    let mut out = HashSet::new();
    for pref in prefixes {
        if let Some(p) = pref.get("ipv4Prefix").and_then(Value::as_str) {
            if let Ok(net) = p.parse::<IpNet>() {
                out.insert(net);
            }
        } else if let Some(p) = pref.get("ipv6Prefix").and_then(Value::as_str)
            && let Ok(net) = p.parse::<IpNet>()
        {
            out.insert(net);
        }
    }
    Ok(out)
}

/// Fetches the Azure IP ranges using the default download page.
///
/// # Errors
///
/// Returns [`crate::error::GuardCoreError::CloudProvider`],
/// [`crate::error::GuardCoreError::Http`], or
/// [`crate::error::GuardCoreError::Json`] on failure.
pub async fn fetch_azure_ip_ranges() -> Result<HashSet<IpNet>> {
    fetch_azure_ip_ranges_from(DEFAULT_AZURE_URL).await
}

/// Fetches the Azure IP ranges by scraping the supplied details page for the
/// download URL.
///
/// # Errors
///
/// Returns [`crate::error::GuardCoreError::CloudProvider`] when no download
/// URL can be parsed, or [`crate::error::GuardCoreError::Http`] /
/// [`crate::error::GuardCoreError::Json`] on transport failures.
pub async fn fetch_azure_ip_ranges_from(details_url: &str) -> Result<HashSet<IpNet>> {
    let client = client();
    let user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                     AppleWebKit/537.36 (KHTML, like Gecko) \
                     Chrome/91.0.4472.124 Safari/537.36";
    let resp = client
        .get(details_url)
        .header("User-Agent", user_agent)
        .send()
        .await?;
    let page_text = resp.text().await?;
    let decoded = decode_html_entities_minimal(&page_text);
    let re = Regex::new(
        r#"href=["'](https?://[^"']{1,500}?\.json)["']"#,
    )
    .expect("static regex");
    let download_url = re
        .captures(&decoded)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| {
            GuardCoreError::CloudProvider("Could not find Azure IP ranges download URL".into())
        })?;

    let resp = client.get(&download_url).send().await?;
    let value: Value = resp.json().await?;

    let values = value.get("values").and_then(Value::as_array);
    let first = values.and_then(|a| a.first());
    let prefixes = first
        .and_then(|v| v.get("properties"))
        .and_then(|p| p.get("addressPrefixes"))
        .and_then(Value::as_array);

    let Some(list) = prefixes else {
        return Ok(HashSet::new());
    };
    Ok(list
        .iter()
        .filter_map(|v| v.as_str().and_then(|s| s.parse::<IpNet>().ok()))
        .collect())
}

fn decode_html_entities_minimal(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn log_range_changes(provider: CloudProvider, old: &HashSet<IpNet>, new: &HashSet<IpNet>) {
    if old == new {
        return;
    }
    let added = new.difference(old).count();
    let removed = old.difference(new).count();
    if added > 0 || removed > 0 {
        info!(
            "Cloud IP range update for {}: +{added} added, -{removed} removed",
            provider.as_str()
        );
    }
}
