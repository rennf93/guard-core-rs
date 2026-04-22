use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::core::checks::base::SecurityCheck;
use crate::core::routing::RouteConfigResolver;
use crate::decorators::base::RouteConfig;
use crate::error::Result;
use crate::handlers::ratelimit::{CheckRateLimitArgs, CreateErrorResponseFn, RateLimitManager};
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{CLIENT_IP_KEY, send_agent_event};

/// Bypass token that disables the rate-limit check on a route.
pub const BYPASS_CHECK_RATE_LIMIT: &str = "rate_limit";
/// [`crate::protocols::request::RequestState`] key marking a whitelisted IP.
pub const IS_WHITELISTED_STATE_KEY: &str = "is_whitelisted";

struct RateLimitCheckParams<'a> {
    request: &'a DynGuardRequest,
    client_ip: &'a str,
    endpoint_path: &'a str,
    rate_limit: Option<u32>,
    rate_limit_window: Option<u64>,
    event_type: &'a str,
    event_reason: &'a str,
    event_extra: Map<String, Value>,
}

/// Enforces per-endpoint, per-route, geo, and global rate limits.
pub struct RateLimitCheck {
    middleware: DynGuardMiddleware,
    route_resolver: Arc<RouteConfigResolver>,
    rate_limit_manager: Arc<RateLimitManager>,
}

impl std::fmt::Debug for RateLimitCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitCheck").finish_non_exhaustive()
    }
}

impl RateLimitCheck {
    /// Creates a new check from the shared middleware, route resolver, and
    /// [`crate::handlers::ratelimit::RateLimitManager`].
    pub fn new(
        middleware: DynGuardMiddleware,
        route_resolver: Arc<RouteConfigResolver>,
        rate_limit_manager: Arc<RateLimitManager>,
    ) -> Self {
        Self { middleware, route_resolver, rate_limit_manager }
    }

    fn build_error_response_fn(&self) -> CreateErrorResponseFn {
        let middleware = self.middleware.clone();
        Arc::new(move |status_code, message| {
            let middleware = middleware.clone();
            Box::pin(async move { middleware.create_error_response(status_code, &message).await })
        })
    }

    async fn apply_rate_limit_check(
        &self,
        params: RateLimitCheckParams<'_>,
    ) -> Result<Option<DynGuardResponse>> {
        let RateLimitCheckParams {
            request,
            client_ip,
            endpoint_path,
            rate_limit,
            rate_limit_window,
            event_type,
            event_reason,
            event_extra,
        } = params;
        let create_error_response = self.build_error_response_fn();
        let args = CheckRateLimitArgs {
            request,
            client_ip,
            create_error_response: &create_error_response,
            endpoint_path,
            rate_limit,
            rate_limit_window,
        };
        let result = self.rate_limit_manager.check_rate_limit(args).await?;
        if result.is_none() {
            return Ok(None);
        }

        let config = self.middleware.config();
        let passive_mode = config.passive_mode;
        let agent = self.middleware.agent_handler();
        let action_taken = if passive_mode { "logged_only" } else { "request_blocked" };
        send_agent_event(
            agent.as_ref(),
            event_type,
            client_ip,
            action_taken,
            event_reason,
            Some(request),
            event_extra,
        )
        .await;

        if passive_mode {
            return Ok(None);
        }
        Ok(result)
    }

    async fn check_endpoint_rate_limit(
        &self,
        request: &DynGuardRequest,
        client_ip: &str,
        endpoint_path: &str,
    ) -> Result<Option<DynGuardResponse>> {
        let config = self.middleware.config();
        let Some(&(rate_limit, window)) = config.endpoint_rate_limits.get(endpoint_path) else {
            return Ok(None);
        };
        let reason = format!(
            "Endpoint-specific rate limit exceeded: {rate_limit} requests per {window}s for {endpoint_path}"
        );
        let mut extra: Map<String, Value> = Map::new();
        extra.insert("reason".into(), json!(reason));
        extra.insert("rule_type".into(), json!("endpoint_rate_limit"));
        extra.insert("endpoint".into(), json!(endpoint_path));
        extra.insert("rate_limit".into(), json!(rate_limit));
        extra.insert("window".into(), json!(window));
        self.apply_rate_limit_check(RateLimitCheckParams {
            request,
            client_ip,
            endpoint_path,
            rate_limit: Some(rate_limit),
            rate_limit_window: Some(window),
            event_type: "dynamic_rule_violation",
            event_reason: &reason,
            event_extra: extra,
        })
        .await
    }

    async fn check_route_rate_limit(
        &self,
        request: &DynGuardRequest,
        client_ip: &str,
        route_config: Option<&RouteConfig>,
    ) -> Result<Option<DynGuardResponse>> {
        let Some(rc) = route_config else { return Ok(None) };
        let Some(rate_limit) = rc.rate_limit else { return Ok(None) };
        let window = rc.rate_limit_window.unwrap_or(60);
        let reason = format!(
            "Route-specific rate limit exceeded: {rate_limit} requests per {window}s"
        );
        let mut extra: Map<String, Value> = Map::new();
        extra.insert("decorator_type".into(), json!("rate_limiting"));
        extra.insert("violation_type".into(), json!("rate_limit"));
        extra.insert("rate_limit".into(), json!(rate_limit));
        extra.insert("window".into(), json!(window));
        let endpoint_path = request.url_path();
        self.apply_rate_limit_check(RateLimitCheckParams {
            request,
            client_ip,
            endpoint_path: &endpoint_path,
            rate_limit: Some(rate_limit),
            rate_limit_window: Some(window),
            event_type: "decorator_violation",
            event_reason: &reason,
            event_extra: extra,
        })
        .await
    }

    async fn check_geo_rate_limit(
        &self,
        request: &DynGuardRequest,
        client_ip: &str,
        route_config: Option<&RouteConfig>,
    ) -> Result<Option<DynGuardResponse>> {
        let Some(rc) = route_config else { return Ok(None) };
        let Some(ref limits) = rc.geo_rate_limits else { return Ok(None) };
        if limits.is_empty() {
            return Ok(None);
        }
        let config = self.middleware.config();
        let Some(geo_handler) = config.geo_ip_handler.clone() else {
            return Ok(None);
        };
        let country = geo_handler.get_country(client_ip);

        let (rate_limit, window, country_label) = if let Some(ref country_code) = country
            && let Some(&(limit, win)) = limits.get(country_code)
        {
            (limit, win, country_code.clone())
        } else if let Some(&(limit, win)) = limits.get("*") {
            (limit, win, country.unwrap_or_else(|| "unknown".into()))
        } else {
            return Ok(None);
        };

        let reason = format!(
            "Geo rate limit exceeded for {country_label}: {rate_limit} requests per {window}s"
        );
        let mut extra: Map<String, Value> = Map::new();
        extra.insert("decorator_type".into(), json!("geo_rate_limiting"));
        extra.insert("violation_type".into(), json!("geo_rate_limit"));
        extra.insert("rate_limit".into(), json!(rate_limit));
        extra.insert("window".into(), json!(window));
        let endpoint_path = request.url_path();
        self.apply_rate_limit_check(RateLimitCheckParams {
            request,
            client_ip,
            endpoint_path: &endpoint_path,
            rate_limit: Some(rate_limit),
            rate_limit_window: Some(window),
            event_type: "decorator_violation",
            event_reason: &reason,
            event_extra: extra,
        })
        .await
    }

    async fn check_global_rate_limit(
        &self,
        request: &DynGuardRequest,
        client_ip: &str,
    ) -> Result<Option<DynGuardResponse>> {
        let create_error_response = self.build_error_response_fn();
        let args = CheckRateLimitArgs {
            request,
            client_ip,
            create_error_response: &create_error_response,
            endpoint_path: "",
            rate_limit: None,
            rate_limit_window: None,
        };
        let result = self.rate_limit_manager.check_rate_limit(args).await?;
        if result.is_some() && self.middleware.config().passive_mode {
            return Ok(None);
        }
        Ok(result)
    }
}

#[async_trait]
impl SecurityCheck for RateLimitCheck {
    fn check_name(&self) -> &'static str {
        "rate_limit"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        if request.state().get_bool(IS_WHITELISTED_STATE_KEY).unwrap_or(false) {
            return Ok(None);
        }
        let Some(client_ip) = request.state().get_str(CLIENT_IP_KEY) else {
            return Ok(None);
        };
        let route_config = self.route_resolver.get_route_config(request);
        if let Some(ref rc) = route_config
            && rc.bypassed_checks.iter().any(|c| c == BYPASS_CHECK_RATE_LIMIT)
        {
            return Ok(None);
        }

        let endpoint_path = request.url_path();

        if let Some(response) = self
            .check_endpoint_rate_limit(request, &client_ip, &endpoint_path)
            .await?
        {
            return Ok(Some(response));
        }
        if let Some(response) = self
            .check_route_rate_limit(request, &client_ip, route_config.as_ref())
            .await?
        {
            return Ok(Some(response));
        }
        if let Some(response) = self
            .check_geo_rate_limit(request, &client_ip, route_config.as_ref())
            .await?
        {
            return Ok(Some(response));
        }
        self.check_global_rate_limit(request, &client_ip).await
    }
}
