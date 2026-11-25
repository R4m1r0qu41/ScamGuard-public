//! MVP detector modules (concept spec "Detection Modules"). Each is
//! independent (RFC-001 §11) and communicates only through
//! `types::DetectorOutput`. Not implemented offline, by honest necessity:
//! domain age/WHOIS/DNS/TLS (needs feeds), link sandboxing (needs a
//! sandbox), behavioral/graph analysis (needs platform telemetry) — see
//! `docs/requirements.md` for the deferral record.

pub mod asks;
pub mod command;
pub mod domain;
pub mod identity;
pub mod intent;
pub mod promo;
