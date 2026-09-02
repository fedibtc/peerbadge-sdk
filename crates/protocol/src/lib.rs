//! Core types for the PeerBadge protocol.
//!
//! This crate intentionally keeps application semantics out of the core
//! protocol. Credential `info` and `blind_msg` fields are arbitrary JSON values;
//! callers decide what schema, holder identifiers, and claims mean.

pub mod authorization;
pub mod canonical;
pub mod error;
pub mod holder;
pub mod issuer;
mod serde;
pub mod types;
pub mod verifier;

pub use authorization::*;
pub use canonical::*;
pub use error::*;
pub use holder::*;
pub use issuer::*;
pub use types::*;
pub use verifier::*;

#[cfg(test)]
mod tests;
