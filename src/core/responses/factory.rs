//! Factory producing error responses, HTTPS redirects, and processed
//! outgoing responses.

use crate::core::responses::context::ResponseContext;
use crate::protocols::response::DynGuardResponse;

/// Constructs framework-agnostic error responses and applies the configured
/// security headers to outbound responses.
#[derive(Clone, Debug)]
pub struct ErrorResponseFactory {
    context: ResponseContext,
}

impl ErrorResponseFactory {
    /// Creates a factory bound to the supplied
    /// [`crate::core::responses::context::ResponseContext`].
    pub const fn new(context: ResponseContext) -> Self {
        Self { context }
    }

    /// Returns an error response with `status_code` and the corresponding
    /// body from [`crate::models::SecurityConfig::custom_error_responses`]
    /// (falling back to `default_message`).
    pub fn create_error_response(&self, status_code: u16, default_message: &str) -> DynGuardResponse {
        let message = self
            .context
            .config
            .custom_error_responses
            .get(&status_code)
            .cloned()
            .unwrap_or_else(|| default_message.to_string());
        self.context
            .response_factory
            .create_response(&message, status_code)
    }

    /// Returns a `301` redirect to `url`.
    pub fn create_https_redirect(&self, url: &str) -> DynGuardResponse {
        self.context
            .response_factory
            .create_redirect_response(url, 301)
    }

    /// Applies the configured security headers to `response` and returns it.
    pub fn process_response(&self, response: DynGuardResponse) -> DynGuardResponse {
        if let Some(ref headers) = self.context.config.security_headers
            && headers.enabled
        {
            apply_security_headers(&response, headers);
        }
        response
    }
}

fn apply_security_headers(
    response: &DynGuardResponse,
    headers: &crate::models::SecurityHeadersConfig,
) {
    let hsts_value = format!(
        "max-age={}{}{}",
        headers.hsts.max_age,
        if headers.hsts.include_subdomains { "; includeSubDomains" } else { "" },
        if headers.hsts.preload { "; preload" } else { "" }
    );
    response.set_header("Strict-Transport-Security", &hsts_value);
    if let Some(ref csp) = headers.csp {
        response.set_header("Content-Security-Policy", csp);
    }
    response.set_header("X-Frame-Options", &headers.frame_options);
    response.set_header("X-Content-Type-Options", &headers.content_type_options);
    response.set_header("X-XSS-Protection", &headers.xss_protection);
    response.set_header("Referrer-Policy", &headers.referrer_policy);
    response.set_header("Permissions-Policy", &headers.permissions_policy);
    if let Some(ref custom) = headers.custom {
        for (k, v) in custom {
            response.set_header(k, v);
        }
    }
}
