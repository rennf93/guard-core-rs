use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::core::checks::base::SecurityCheck;
use crate::core::routing::RouteConfigResolver;
use crate::error::Result;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{CLIENT_IP_KEY, extract_client_ip, is_trusted_proxy, send_agent_event};

/// Forces HTTP requests to HTTPS when
/// [`crate::models::SecurityConfig::enforce_https`] or the route-level setting
/// is enabled.
pub struct HttpsEnforcementCheck {
    middleware: DynGuardMiddleware,
    route_resolver: Arc<RouteConfigResolver>,
}

impl std::fmt::Debug for HttpsEnforcementCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsEnforcementCheck").finish_non_exhaustive()
    }
}

impl HttpsEnforcementCheck {
    /// Creates a new check from the shared middleware and route resolver.
    pub const fn new(
        middleware: DynGuardMiddleware,
        route_resolver: Arc<RouteConfigResolver>,
    ) -> Self {
        Self { middleware, route_resolver }
    }

    fn is_request_https(&self, request: &DynGuardRequest) -> bool {
        let config = self.middleware.config();
        let mut is_https = request.url_scheme() == "https";
        if config.trust_x_forwarded_proto
            && !config.trusted_proxies.is_empty()
            && let Some(client_host) = request.client_host()
            && is_trusted_proxy(&client_host, &config.trusted_proxies)
            && let Some(forwarded_proto) = request.header("X-Forwarded-Proto")
            && forwarded_proto.eq_ignore_ascii_case("https")
        {
            is_https = true;
        }
        is_https
    }
}

#[async_trait]
impl SecurityCheck for HttpsEnforcementCheck {
    fn check_name(&self) -> &'static str {
        "https_enforcement"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        let config = self.middleware.config();
        let route_config = self.route_resolver.get_route_config(request);
        let https_required = route_config
            .as_ref()
            .map_or(config.enforce_https, |rc| rc.require_https);
        if !https_required {
            return Ok(None);
        }
        if self.is_request_https(request) {
            return Ok(None);
        }

        let agent = self.middleware.agent_handler();
        let client_ip = match request.state().get_str(CLIENT_IP_KEY) {
            Some(ip) => ip,
            None => extract_client_ip(request, &config, agent.as_ref()).await,
        };

        let mut extra: Map<String, Value> = Map::new();
        extra.insert("violation".into(), json!("https_required"));
        send_agent_event(
            agent.as_ref(),
            "security_violation",
            &client_ip,
            "redirect",
            "HTTPS required",
            Some(request),
            extra,
        )
        .await;

        if !config.passive_mode {
            let redirect_url = request.url_replace_scheme("https");
            let response = self
                .middleware
                .guard_response_factory()
                .create_redirect_response(&redirect_url, 301);
            return Ok(Some(response));
        }
        Ok(None)
    }
}
