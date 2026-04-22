//! Concrete [`crate::core::checks::base::SecurityCheck`] implementations.
//!
//! Each sub-module houses one check in the pipeline; they are ordered in the
//! same sequence that [`crate::core::checks::pipeline::SecurityCheckPipeline`]
//! evaluates them.

pub mod authentication;
pub mod cloud_ip_refresh;
#[cfg(feature = "cloud-providers")]
pub mod cloud_provider;
pub mod custom_request;
pub mod custom_validators;
pub mod emergency_mode;
pub mod https_enforcement;
pub mod ip_security;
pub mod rate_limit;
pub mod referrer;
pub mod request_logging;
pub mod request_size_content;
pub mod required_headers;
pub mod route_config;
pub mod suspicious_activity;
pub mod time_window;
pub mod user_agent;

pub use authentication::AuthenticationCheck;
pub use cloud_ip_refresh::CloudIpRefreshCheck;
#[cfg(feature = "cloud-providers")]
pub use cloud_provider::CloudProviderCheck;
pub use custom_request::CustomRequestCheck;
pub use custom_validators::CustomValidatorsCheck;
pub use emergency_mode::EmergencyModeCheck;
pub use https_enforcement::HttpsEnforcementCheck;
pub use ip_security::IpSecurityCheck;
pub use rate_limit::RateLimitCheck;
pub use referrer::ReferrerCheck;
pub use request_logging::RequestLoggingCheck;
pub use request_size_content::RequestSizeContentCheck;
pub use required_headers::RequiredHeadersCheck;
pub use route_config::RouteConfigCheck;
pub use suspicious_activity::SuspiciousActivityCheck;
pub use time_window::TimeWindowCheck;
pub use user_agent::UserAgentCheck;
