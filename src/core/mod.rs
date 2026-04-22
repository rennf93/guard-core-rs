//! Core architecture modules that compose the request pipeline.
//!
//! Each sub-module encapsulates one responsibility: security checks live in
//! [`crate::core::checks`], the chain-of-responsibility runner is
//! [`crate::core::checks::pipeline`], response handling lives in
//! [`crate::core::responses`], routing is
//! [`crate::core::routing`], request validation is
//! [`crate::core::validation`], bypass handling is
//! [`crate::core::bypass`], behavioural processing is
//! [`crate::core::behavioral`], event dispatch is
//! [`crate::core::events`], and handler bootstrap is
//! [`crate::core::initialization`].

pub mod behavioral;
pub mod bypass;
pub mod checks;
pub mod events;
pub mod initialization;
pub mod responses;
pub mod routing;
pub mod validation;
