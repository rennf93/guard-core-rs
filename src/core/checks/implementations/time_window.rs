use std::sync::Arc;

use async_trait::async_trait;
use chrono::{NaiveTime, Timelike, Utc};
use serde_json::{Map, Value, json};

use crate::core::checks::base::SecurityCheck;
use crate::core::routing::RouteConfigResolver;
use crate::error::Result;
use crate::models::LogLevel;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{CLIENT_IP_KEY, LogType, extract_client_ip, log_activity, send_agent_event};

/// Rejects requests received outside the `[time_window_start, time_window_end]`
/// range declared on the route.
pub struct TimeWindowCheck {
    middleware: DynGuardMiddleware,
    route_resolver: Arc<RouteConfigResolver>,
}

impl std::fmt::Debug for TimeWindowCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimeWindowCheck").finish_non_exhaustive()
    }
}

impl TimeWindowCheck {
    /// Creates a new check from the shared middleware and route resolver.
    pub const fn new(
        middleware: DynGuardMiddleware,
        route_resolver: Arc<RouteConfigResolver>,
    ) -> Self {
        Self { middleware, route_resolver }
    }
}

#[async_trait]
impl SecurityCheck for TimeWindowCheck {
    fn check_name(&self) -> &'static str {
        "time_window"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        let Some(route_config) = self.route_resolver.get_route_config(request) else {
            return Ok(None);
        };
        let (Some(start), Some(end)) = (route_config.time_window_start, route_config.time_window_end)
        else {
            return Ok(None);
        };

        if is_time_allowed(start, end) {
            return Ok(None);
        }

        let config = self.middleware.config();
        let passive_mode = config.passive_mode;
        let suspicious_level = config.log_suspicious_level;
        let reason = "Access outside allowed time window";

        log_activity(
            request,
            LogType::Suspicious { reason, passive_mode, trigger_info: "" },
            suspicious_level.or(Some(LogLevel::Warning)),
        )
        .await;

        let agent = self.middleware.agent_handler();
        let client_ip = match request.state().get_str(CLIENT_IP_KEY) {
            Some(ip) => ip,
            None => extract_client_ip(request, &config, agent.as_ref()).await,
        };

        let action_taken = if passive_mode { "logged_only" } else { "request_blocked" };
        let mut extra: Map<String, Value> = Map::new();
        extra.insert("decorator_type".into(), json!("advanced"));
        extra.insert("violation_type".into(), json!("time_restriction"));
        send_agent_event(
            agent.as_ref(),
            "decorator_violation",
            &client_ip,
            action_taken,
            reason,
            Some(request),
            extra,
        )
        .await;

        if !passive_mode {
            return Ok(Some(
                self.middleware
                    .create_error_response(403, "Access not allowed at this time")
                    .await?,
            ));
        }
        Ok(None)
    }
}

fn is_time_allowed(start: NaiveTime, end: NaiveTime) -> bool {
    let now = Utc::now().time();
    let hm_now = now.hour() * 60 + now.minute();
    let hm_start = start.hour() * 60 + start.minute();
    let hm_end = end.hour() * 60 + end.minute();
    if hm_start > hm_end {
        hm_now >= hm_start || hm_now <= hm_end
    } else {
        hm_now >= hm_start && hm_now <= hm_end
    }
}
