//! First-party credential schemas layered on the schema-agnostic core
//! protocol crate.
//!
//! The protocol crate treats `Credential.info` and `Credential.blind_msg` as
//! free-form JSON. Each schema module here owns one `info.schema` vocabulary
//! end to end: the issuance-input constructors and the verifier-side parser
//! live together, so issuers and verifiers in different codebases share one
//! definition instead of re-deriving it.
//!
//! Schema parsing is layered *on top of* cryptographic verification, never a
//! substitute for it: callers must first verify the `SignedCredential` (and,
//! where applicable, the holder authorization) through the protocol crate,
//! then parse the payload with the matching `parse_*` function.

pub mod trust_score;

pub use trust_score::*;
