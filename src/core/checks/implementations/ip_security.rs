use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::core::checks::base::SecurityCheck;
use crate::core::checks::helpers::check_route_ip_access;
use crate::core::routing::RouteConfigResolver;
use crate::decorators::base::RouteConfig;
use crate::error::Result;
use crate::handlers::ipban::IPBanManager;
use crate::models::LogLevel;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{CLIENT_IP_KEY, LogType, is_ip_allowed, log_activity, send_agent_event};

/// Bypass token that disables the IP-ban check on a route.
pub const BYPASS_CHECK_IP_BAN: &str = "ip_ban";
/// Bypass token that disables the IP allow/block-list check on a route.
pub const BYPASS_CHECK_IP: &str = "ip";
/// [`crate::protocols::request::RequestState`] key marking a whitelisted IP.
pub const IS_WHITELISTED_STATE_KEY: &str = "is_whitelisted";

/// Enforces IP ban, route-level allow/block lists, and global lists.
pub struct IpSecurityCheck {
    middleware: DynGuardMiddleware,
    route_resolver: Arc<RouteConfigResolver>,
    ipban_manager: Arc<IPBanManager>,
}

impl std::fmt::Debug for IpSecurityCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpSecurityCheck").finish_non_exhaustive()
    }
}

impl IpSecurityCheck {
    /// Creates a new check from the shared middleware, route resolver, and
    /// [`crate::handlers::ipban::IPBanManager`].
    pub const fn new(
        middleware: DynGuardMiddleware,
        route_resolver: Arc<RouteConfigResolver>,
        ipban_manager: Arc<IPBanManager>,
    ) -> Self {
        Self { middleware, route_resolver, ipban_manager }
    }

    async fn check_banned_ip(
        &self,
        request: &DynGuardRequest,
        client_ip: &str,
        route_config: Option<&RouteConfig>,
    ) -> Result<Option<DynGuardResponse>> {
        if let Some(rc) = route_config
            && rc.bypassed_checks.iter().any(|c| c == BYPASS_CHECK_IP_BAN)
        {
            return Ok(None);
        }
        if !self.ipban_manager.is_ip_banned(client_ip).await? {
            return Ok(None);
        }
        let config = self.middleware.config();
        let passive_mode = config.passive_mode;
        let suspicious_level = config.log_suspicious_level;
        log_activity(
            request,
            LogType::Suspicious {
                reason: &format!("Banned IP attempted access: {client_ip}"),
                passive_mode,
                trigger_info: "",
            },
            suspicious_level.or(Some(LogLevel::Warning)),
        )
        .await;
        if !passive_mode {
            return Ok(Some(
                self.middleware.create_error_response(403, "IP address banned").await?,
            ));
        }
        Ok(None)
    }

    async fn check_route_ip_restrictions(
        &self,
        request: &DynGuardRequest,
        client_ip: &str,
        route_config: &RouteConfig,
    ) -> Result<Option<DynGuardResponse>> {
        let geo_handler = self.middleware.geo_ip_handler();
        let route_allowed = check_route_ip_access(client_ip, route_config, geo_handler.as_ref());
        if route_allowed.is_none() || route_allowed == Some(true) {
            return Ok(None);
        }

        let config = self.middleware.config();
        let passive_mode = config.passive_mode;
        let suspicious_level = config.log_suspicious_level;
        log_activity(
            request,
            LogType::Suspicious {
                reason: &format!("IP not allowed by route config: {client_ip}"),
                passive_mode,
                trigger_info: "",
            },
            suspicious_level.or(Some(LogLevel::Warning)),
        )
        .await;

        let agent = self.middleware.agent_handler();
        let action_taken = if passive_mode { "logged_only" } else { "request_blocked" };
        let mut extra: Map<String, Value> = Map::new();
        extra.insert("decorator_type".into(), json!("access_control"));
        extra.insert("violation_type".into(), json!("ip_restriction"));
        send_agent_event(
            agent.as_ref(),
            "decorator_violation",
            client_ip,
            action_taken,
            &format!("IP {client_ip} blocked"),
            Some(request),
            extra,
        )
        .await;

        if !passive_mode {
            return Ok(Some(self.middleware.create_error_response(403, "Forbidden").await?));
        }
        Ok(None)
    }

    async fn check_global_ip_restrictions(
        &self,
        request: &DynGuardRequest,
        client_ip: &str,
    ) -> Result<Option<DynGuardResponse>> {
        let config = self.middleware.config();
        let geo_handler = self.middleware.geo_ip_handler();
        let is_allowed = is_ip_allowed(client_ip, &config, geo_handler.as_ref()).await;
        request.state().set_bool(
            IS_WHITELISTED_STATE_KEY,
            is_allowed && config.whitelist.is_some(),
        );
        if is_allowed {
            return Ok(None);
        }

        let passive_mode = config.passive_mode;
        let suspicious_level = config.log_suspicious_level;
        log_activity(
            request,
            LogType::Suspicious {
                reason: &format!("IP not allowed: {client_ip}"),
                passive_mode,
                trigger_info: "",
            },
            suspicious_level.or(Some(LogLevel::Warning)),
        )
        .await;

        let agent = self.middleware.agent_handler();
        let action_taken = if passive_mode { "logged_only" } else { "request_blocked" };
        let mut extra: Map<String, Value> = Map::new();
        extra.insert("ip_address".into(), json!(client_ip));
        extra.insert("filter_type".into(), json!("global"));
        send_agent_event(
            agent.as_ref(),
            "ip_blocked",
            client_ip,
            action_taken,
            &format!("IP {client_ip} not in global allowlist/blocklist"),
            Some(request),
            extra,
        )
        .await;

        if !passive_mode {
            return Ok(Some(self.middleware.create_error_response(403, "Forbidden").await?));
        }
        Ok(None)
    }
}

#[async_trait]
impl SecurityCheck for IpSecurityCheck {
    fn check_name(&self) -> &'static str {
        "ip_security"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        let Some(client_ip) = request.state().get_str(CLIENT_IP_KEY) else {
            return Ok(None);
        };
        let route_config = self.route_resolver.get_route_config(request);

        if let Some(ban_response) = self
            .check_banned_ip(request, &client_ip, route_config.as_ref())
            .await?
        {
            return Ok(Some(ban_response));
        }

        if let Some(ref rc) = route_config
            && rc.bypassed_checks.iter().any(|c| c == BYPASS_CHECK_IP)
        {
            return Ok(None);
        }

        if let Some(rc) = route_config {
            return self.check_route_ip_restrictions(request, &client_ip, &rc).await;
        }

        self.check_global_ip_restrictions(request, &client_ip).await
    }
}
