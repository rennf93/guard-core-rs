//! Route-level security decorators.
//!
//! Contains [`crate::decorators::RouteConfig`] (the per-route policy
//! container), [`crate::decorators::SecurityDecorator`] (registry and event
//! dispatcher), and [`crate::decorators::get_route_decorator_config`] (the
//! middleware-side resolver).

pub mod base;

pub use base::{
    BaseSecurityDecorator, BaseSecurityMixin, CustomValidator, ROUTE_ID_STATE_KEY, RouteConfig,
    SecurityDecorator, get_route_decorator_config,
};
