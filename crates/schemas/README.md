# peerbadge-schemas

Canonical definitions of the first-party credential schemas carried in
`Credential.info` / `Credential.blind_msg`.

The PeerBadge protocol is deliberately schema-agnostic: `info` and
`blind_msg` are free-form JSON. This crate is the single source of truth for
what first-party consumers (the PeerBadge app, the manifold verifiers) put in
those fields, so that issuers and verifiers cannot drift apart under the same
schema version string.

Consumers should construct issuance inputs with the `*_info_*` /
`*_blind_msg_*` helpers and validate received credentials with the
`parse_*` functions — never hand-build or hand-parse the JSON.

Golden vectors under `fixtures/` pin the exact wire shape; both this crate's
tests and downstream repos' CI verify against them.
