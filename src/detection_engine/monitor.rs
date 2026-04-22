//! Runtime performance monitoring for detection-engine patterns.
//!
//! [`crate::detection_engine::monitor::PerformanceMonitor`] records per-
//! execution timings, computes per-pattern statistics, detects anomalies, and
//! forwards them to the Guard Agent and registered callbacks.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;

use crate::protocols::agent::DynAgentHandler;

const MAX_PATTERN_LENGTH: usize = 100;
const TRUNCATED_SUFFIX: &str = "...[truncated]";
const RECENT_TIMES_CAP: usize = 100;

/// A single pattern execution metric recorded by the monitor.
#[derive(Debug, Clone)]
pub struct PerformanceMetric {
    /// Pattern source (truncated to 100 chars).
    pub pattern: String,
    /// Execution time in seconds.
    pub execution_time: f64,
    /// Length of the content the pattern ran against.
    pub content_length: usize,
    /// UTC timestamp the metric was recorded.
    pub timestamp: DateTime<Utc>,
    /// Whether the pattern matched the input.
    pub matched: bool,
    /// Whether execution timed out before completing.
    pub timeout: bool,
}

/// Borrowed input to
/// [`crate::detection_engine::monitor::PerformanceMonitor::record_metric`].
///
/// Carried as a struct so the hot-path call site stays readable and avoids
/// long parameter lists.
#[derive(Debug, Clone, Copy)]
pub struct RecordMetricInput<'a> {
    /// Pattern source string.
    pub pattern: &'a str,
    /// Execution time in seconds.
    pub execution_time: f64,
    /// Length of the content the pattern ran against.
    pub content_length: usize,
    /// Whether the pattern matched the input.
    pub matched: bool,
    /// Whether execution timed out before completing.
    pub timeout: bool,
    /// Optional Guard Agent handler used for anomaly event forwarding.
    pub agent_handler: Option<&'a DynAgentHandler>,
    /// Optional correlation id attached to anomaly events.
    pub correlation_id: Option<&'a str>,
}

/// Aggregated statistics for a single pattern tracked by the monitor.
#[derive(Debug, Clone)]
pub struct PatternStats {
    /// Pattern source (truncated to 100 chars).
    pub pattern: String,
    /// Total number of times the pattern has been executed.
    pub total_executions: u64,
    /// Total number of executions that matched.
    pub total_matches: u64,
    /// Total number of executions that timed out.
    pub total_timeouts: u64,
    /// Rolling average execution time in seconds.
    pub avg_execution_time: f64,
    /// Observed maximum execution time in seconds.
    pub max_execution_time: f64,
    /// Observed minimum execution time in seconds.
    pub min_execution_time: f64,
    /// Sliding window of the most recent (non-timeout) execution times.
    pub recent_times: VecDeque<f64>,
}

impl PatternStats {
    /// Creates an empty stats record for `pattern`.
    pub fn new(pattern: String) -> Self {
        Self {
            pattern,
            total_executions: 0,
            total_matches: 0,
            total_timeouts: 0,
            avg_execution_time: 0.0,
            max_execution_time: 0.0,
            min_execution_time: f64::INFINITY,
            recent_times: VecDeque::with_capacity(RECENT_TIMES_CAP),
        }
    }
}

/// Callback invoked whenever the monitor detects a pattern anomaly.
///
/// The argument is a sanitised JSON payload suitable for external
/// propagation.
pub type AnomalyCallback = Arc<dyn Fn(&Value) + Send + Sync>;

struct MonitorInner {
    pattern_stats: HashMap<String, PatternStats>,
    recent_metrics: VecDeque<PerformanceMetric>,
}

/// Records per-pattern execution metrics and surfaces anomalies.
///
/// Thresholds are clamped on construction so values outside the supported
/// ranges are snapped to the nearest valid bound.
///
/// # Examples
///
/// ```no_run
/// use guard_core_rs::detection_engine::monitor::{PerformanceMonitor, RecordMetricInput};
///
/// # async fn run() {
/// let monitor = PerformanceMonitor::new(3.0, 0.1, 1000, 1000);
/// monitor.record_metric(RecordMetricInput {
///     pattern: "<script",
///     execution_time: 0.002,
///     content_length: 128,
///     matched: false,
///     timeout: false,
///     agent_handler: None,
///     correlation_id: None,
/// }).await;
/// # }
/// ```
pub struct PerformanceMonitor {
    /// Z-score cut-off above which execution times are flagged as anomalies.
    pub anomaly_threshold: f64,
    /// Slow-pattern threshold in seconds.
    pub slow_pattern_threshold: f64,
    /// Number of recent metrics retained in memory.
    pub history_size: usize,
    /// Maximum number of distinct patterns tracked simultaneously.
    pub max_tracked_patterns: usize,
    inner: Arc<Mutex<MonitorInner>>,
    callbacks: parking_lot::RwLock<Vec<AnomalyCallback>>,
}

impl std::fmt::Debug for PerformanceMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerformanceMonitor")
            .field("anomaly_threshold", &self.anomaly_threshold)
            .field("slow_pattern_threshold", &self.slow_pattern_threshold)
            .field("history_size", &self.history_size)
            .field("max_tracked_patterns", &self.max_tracked_patterns)
            .finish()
    }
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new(3.0, 0.1, 1000, 1000)
    }
}

impl PerformanceMonitor {
    /// Constructs a new monitor. Thresholds outside their documented ranges
    /// are clamped (e.g. `anomaly_threshold` to `1.0..=10.0`).
    pub fn new(
        anomaly_threshold: f64,
        slow_pattern_threshold: f64,
        history_size: usize,
        max_tracked_patterns: usize,
    ) -> Self {
        let anomaly_threshold = anomaly_threshold.clamp(1.0, 10.0);
        let slow_pattern_threshold = slow_pattern_threshold.clamp(0.01, 10.0);
        let history_size = history_size.clamp(100, 10_000);
        let max_tracked_patterns = max_tracked_patterns.clamp(100, 5_000);
        Self {
            anomaly_threshold,
            slow_pattern_threshold,
            history_size,
            max_tracked_patterns,
            inner: Arc::new(Mutex::new(MonitorInner {
                pattern_stats: HashMap::new(),
                recent_metrics: VecDeque::with_capacity(history_size),
            })),
            callbacks: parking_lot::RwLock::new(Vec::new()),
        }
    }

    fn truncate_pattern(pattern: &str) -> String {
        if pattern.len() > MAX_PATTERN_LENGTH {
            format!("{}{TRUNCATED_SUFFIX}", &pattern[..MAX_PATTERN_LENGTH])
        } else {
            pattern.to_string()
        }
    }

    /// Records a single execution metric and runs anomaly detection.
    pub async fn record_metric(
        &self,
        metric_input: RecordMetricInput<'_>,
    ) {
        let RecordMetricInput {
            pattern,
            execution_time,
            content_length,
            matched,
            timeout,
            agent_handler,
            correlation_id,
        } = metric_input;
        let pattern = Self::truncate_pattern(pattern);
        let execution_time = execution_time.max(0.0);

        let metric = PerformanceMetric {
            pattern: pattern.clone(),
            execution_time,
            content_length,
            timestamp: Utc::now(),
            matched,
            timeout,
        };

        {
            let mut inner = self.inner.lock().await;
            while inner.recent_metrics.len() >= self.history_size {
                inner.recent_metrics.pop_front();
            }
            inner.recent_metrics.push_back(metric.clone());

            if !inner.pattern_stats.contains_key(&pattern) {
                if inner.pattern_stats.len() >= self.max_tracked_patterns {
                    if let Some(oldest) = inner.pattern_stats.keys().next().cloned() {
                        inner.pattern_stats.remove(&oldest);
                    }
                }
                inner.pattern_stats.insert(pattern.clone(), PatternStats::new(pattern.clone()));
            }

            let stats = inner.pattern_stats.get_mut(&pattern).expect("just inserted");
            stats.total_executions += 1;
            if matched {
                stats.total_matches += 1;
            }
            if timeout {
                stats.total_timeouts += 1;
            }
            if !timeout {
                while stats.recent_times.len() >= RECENT_TIMES_CAP {
                    stats.recent_times.pop_front();
                }
                stats.recent_times.push_back(execution_time);
                if execution_time > stats.max_execution_time {
                    stats.max_execution_time = execution_time;
                }
                if execution_time < stats.min_execution_time {
                    stats.min_execution_time = execution_time;
                }
                if !stats.recent_times.is_empty() {
                    let sum: f64 = stats.recent_times.iter().sum();
                    stats.avg_execution_time = sum / stats.recent_times.len() as f64;
                }
            }
        }

        self.check_anomalies(&metric, agent_handler, correlation_id).await;
    }

    fn detect_timeout_anomaly(metric: &PerformanceMetric) -> Option<Map<String, Value>> {
        if metric.timeout {
            let mut m = Map::new();
            m.insert("type".into(), json!("timeout"));
            m.insert("pattern".into(), json!(metric.pattern));
            m.insert("content_length".into(), json!(metric.content_length));
            Some(m)
        } else {
            None
        }
    }

    fn detect_slow_execution_anomaly(&self, metric: &PerformanceMetric) -> Option<Map<String, Value>> {
        if !metric.timeout && metric.execution_time > self.slow_pattern_threshold {
            let mut m = Map::new();
            m.insert("type".into(), json!("slow_execution"));
            m.insert("pattern".into(), json!(metric.pattern));
            m.insert("execution_time".into(), json!(metric.execution_time));
            m.insert("content_length".into(), json!(metric.content_length));
            Some(m)
        } else {
            None
        }
    }

    async fn detect_statistical_anomaly(
        &self,
        metric: &PerformanceMetric,
    ) -> Option<Map<String, Value>> {
        let inner = self.inner.lock().await;
        let stats = inner.pattern_stats.get(&metric.pattern)?;
        if stats.recent_times.len() < 10 {
            return None;
        }
        let times: Vec<f64> = stats.recent_times.iter().copied().collect();
        let n = times.len() as f64;
        if n <= 1.0 {
            return None;
        }
        let avg = times.iter().sum::<f64>() / n;
        let variance = times.iter().map(|t| (t - avg).powi(2)).sum::<f64>() / (n - 1.0);
        let std = variance.sqrt();
        if std <= 0.0 {
            return None;
        }
        let z_score = (metric.execution_time - avg) / std;
        if z_score.abs() > self.anomaly_threshold {
            let mut m = Map::new();
            m.insert("type".into(), json!("statistical_anomaly"));
            m.insert("pattern".into(), json!(metric.pattern));
            m.insert("execution_time".into(), json!(metric.execution_time));
            m.insert("z_score".into(), json!(z_score));
            m.insert("avg_time".into(), json!(avg));
            m.insert("std_time".into(), json!(std));
            Some(m)
        } else {
            None
        }
    }

    async fn send_anomaly_event(
        anomaly: &Map<String, Value>,
        agent_handler: &DynAgentHandler,
        correlation_id: Option<&str>,
    ) {
        let event_type = anomaly
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let mut metadata = anomaly.clone();
        metadata.insert("component".into(), json!("PerformanceMonitor"));
        metadata.insert("correlation_id".into(), json!(correlation_id));
        let event = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "event_type": format!("pattern_anomaly_{event_type}"),
            "ip_address": "system",
            "action_taken": "anomaly_detected",
            "reason": format!("Pattern performance anomaly: {event_type}"),
            "metadata": metadata,
        });
        let _ = agent_handler.send_event(event).await;
    }

    fn sanitize_anomaly(anomaly: &Map<String, Value>) -> Map<String, Value> {
        let mut safe = anomaly.clone();
        if let Some(Value::String(pattern)) = safe.get("pattern").cloned() {
            let truncated = if pattern.len() > 50 {
                format!("{}...", &pattern[..50])
            } else {
                pattern.clone()
            };
            safe.insert("pattern".into(), Value::String(truncated));
            let hash = format!("{:x}", md5_like_hash(&pattern));
            let short = if hash.len() > 8 { &hash[..8] } else { &hash };
            safe.insert("pattern_hash".into(), Value::String(short.into()));
        }
        safe
    }

    async fn notify_callbacks(&self, anomaly: &Map<String, Value>) {
        let safe = Self::sanitize_anomaly(anomaly);
        let safe_value = Value::Object(safe);
        let callbacks = self.callbacks.read().clone();
        for cb in callbacks {
            cb(&safe_value);
        }
    }

    async fn check_anomalies(
        &self,
        metric: &PerformanceMetric,
        agent_handler: Option<&DynAgentHandler>,
        correlation_id: Option<&str>,
    ) {
        let mut anomalies: Vec<Map<String, Value>> = Vec::new();
        if let Some(a) = Self::detect_timeout_anomaly(metric) {
            anomalies.push(a);
        } else if let Some(a) = self.detect_slow_execution_anomaly(metric) {
            anomalies.push(a);
        }
        if let Some(a) = self.detect_statistical_anomaly(metric).await {
            anomalies.push(a);
        }

        if let Some(agent) = agent_handler {
            for a in &anomalies {
                Self::send_anomaly_event(a, agent, correlation_id).await;
            }
        }
        for a in &anomalies {
            self.notify_callbacks(a).await;
        }
    }

    /// Returns a JSON report for `pattern` or [`None`] when it has never been
    /// recorded.
    pub async fn get_pattern_report(&self, pattern: &str) -> Option<Value> {
        let pattern = Self::truncate_pattern(pattern);
        let inner = self.inner.lock().await;
        let stats = inner.pattern_stats.get(&pattern)?;
        let safe_pattern = if pattern.len() > 50 {
            format!("{}...", &pattern[..50])
        } else {
            pattern.clone()
        };
        let hash = format!("{:x}", md5_like_hash(&pattern));
        let short = if hash.len() > 8 { &hash[..8] } else { &hash };
        let total = stats.total_executions.max(1);
        let min_exec = if stats.min_execution_time.is_infinite() {
            0.0
        } else {
            stats.min_execution_time
        };
        Some(json!({
            "pattern": safe_pattern,
            "pattern_hash": short,
            "total_executions": stats.total_executions,
            "total_matches": stats.total_matches,
            "total_timeouts": stats.total_timeouts,
            "match_rate": stats.total_matches as f64 / total as f64,
            "timeout_rate": stats.total_timeouts as f64 / total as f64,
            "avg_execution_time": round4(stats.avg_execution_time),
            "max_execution_time": round4(stats.max_execution_time),
            "min_execution_time": round4(min_exec),
        }))
    }

    /// Returns reports for the `limit` slowest tracked patterns, ordered by
    /// descending average execution time.
    pub async fn get_slow_patterns(&self, limit: usize) -> Vec<Value> {
        let inner = self.inner.lock().await;
        let mut ordered: Vec<(f64, String)> = inner
            .pattern_stats
            .iter()
            .filter(|(_, s)| !s.recent_times.is_empty())
            .map(|(p, s)| (s.avg_execution_time, p.clone()))
            .collect();
        ordered.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        drop(inner);
        let mut out = Vec::new();
        for (_, pattern) in ordered.into_iter().take(limit) {
            if let Some(report) = self.get_pattern_report(&pattern).await {
                out.push(report);
            }
        }
        out
    }

    /// Returns reports for patterns that exceed the timeout rate or the
    /// slow-pattern threshold.
    pub async fn get_problematic_patterns(&self) -> Vec<Value> {
        let inner = self.inner.lock().await;
        let mut candidates: Vec<(String, &'static str)> = Vec::new();
        for (pattern, stats) in &inner.pattern_stats {
            if stats.total_executions == 0 {
                continue;
            }
            let timeout_rate = stats.total_timeouts as f64 / stats.total_executions as f64;
            if timeout_rate > 0.1 {
                candidates.push((pattern.clone(), "high_timeout_rate"));
            } else if stats.avg_execution_time > self.slow_pattern_threshold {
                candidates.push((pattern.clone(), "consistently_slow"));
            }
        }
        drop(inner);
        let mut out = Vec::new();
        for (pattern, issue) in candidates {
            if let Some(mut report) = self.get_pattern_report(&pattern).await
                && let Value::Object(ref mut map) = report
            {
                map.insert("issue".into(), json!(issue));
                out.push(report);
            }
        }
        out
    }

    /// Returns a summary snapshot across every recent metric.
    pub async fn get_summary_stats(&self) -> Value {
        let inner = self.inner.lock().await;
        if inner.recent_metrics.is_empty() {
            return json!({
                "total_executions": 0,
                "avg_execution_time": 0.0,
                "timeout_rate": 0.0,
                "match_rate": 0.0,
            });
        }
        let recent_times: Vec<f64> = inner
            .recent_metrics
            .iter()
            .filter(|m| !m.timeout)
            .map(|m| m.execution_time)
            .collect();
        let timeouts = inner.recent_metrics.iter().filter(|m| m.timeout).count();
        let matches = inner.recent_metrics.iter().filter(|m| m.matched).count();
        let total = inner.recent_metrics.len();
        let (avg, mx, mn) = if recent_times.is_empty() {
            (0.0, 0.0, 0.0)
        } else {
            let sum: f64 = recent_times.iter().sum();
            let avg = sum / recent_times.len() as f64;
            let mx = recent_times.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let mn = recent_times.iter().copied().fold(f64::INFINITY, f64::min);
            (avg, mx, mn)
        };
        json!({
            "total_executions": total,
            "avg_execution_time": avg,
            "max_execution_time": mx,
            "min_execution_time": mn,
            "timeout_rate": timeouts as f64 / total as f64,
            "match_rate": matches as f64 / total as f64,
            "total_patterns": inner.pattern_stats.len(),
        })
    }

    /// Registers an [`crate::detection_engine::monitor::AnomalyCallback`]
    /// invoked on every detected anomaly.
    pub fn register_anomaly_callback(&self, callback: AnomalyCallback) {
        self.callbacks.write().push(callback);
    }

    /// Drops every recorded stats and metric.
    pub async fn clear_stats(&self) {
        let mut inner = self.inner.lock().await;
        inner.pattern_stats.clear();
        inner.recent_metrics.clear();
    }

    /// Removes the stats bucket for `pattern`, if any.
    pub async fn remove_pattern_stats(&self, pattern: &str) {
        let mut inner = self.inner.lock().await;
        inner.pattern_stats.remove(pattern);
    }
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn md5_like_hash(s: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    s.hash(&mut hasher);
    hasher.finish()
}
