//! Security checks executed by the request pipeline.
//!
//! This module exposes the [`crate::core::checks::SecurityCheck`] trait, the
//! [`crate::core::checks::SecurityCheckPipeline`] runner, and the concrete
//! implementations under [`crate::core::checks::implementations`]. Shared
//! helper functions live in [`crate::core::checks::helpers`].

pub mod base;
pub mod helpers;
pub mod implementations;
pub mod pipeline;

pub use base::SecurityCheck;
pub use implementations::{
    AuthenticationCheck, CloudIpRefreshCheck, CustomRequestCheck, CustomValidatorsCheck,
    EmergencyModeCheck, HttpsEnforcementCheck, IpSecurityCheck, RateLimitCheck, ReferrerCheck,
    RequestLoggingCheck, RequestSizeContentCheck, RequiredHeadersCheck, RouteConfigCheck,
    SuspiciousActivityCheck, TimeWindowCheck, UserAgentCheck,
};
#[cfg(feature = "cloud-providers")]
pub use implementations::CloudProviderCheck;
pub use pipeline::SecurityCheckPipeline;
