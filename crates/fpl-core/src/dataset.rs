//! Local datasets, compiled in and versioned (`dataset_version` travels in
//! every finding's provenance). Data changes bump the dataset version, not
//! the detector version.

use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Debug, Deserialize)]
pub struct Brand {
    pub name: String,
    pub domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct BrandTargets {
    pub dataset_version: String,
    pub brands: Vec<Brand>,
    pub persons: Vec<String>,
}

impl BrandTargets {
    pub fn is_known_domain(&self, registrable: &str) -> bool {
        self.brands
            .iter()
            .any(|b| b.domains.iter().any(|d| d == registrable))
    }
}

static TARGETS: OnceLock<BrandTargets> = OnceLock::new();

pub fn brand_targets() -> &'static BrandTargets {
    TARGETS.get_or_init(|| {
        serde_json::from_str(include_str!("../../../datasets/brand-targets.v1.json"))
            .expect("bundled brand-targets dataset is valid")
    })
}

/// The operative reason-code registry (registry/reason-codes.v1.json).
#[derive(Debug, Deserialize)]
pub struct ReasonCodeRegistry {
    pub schema_version: String,
    pub codes: Vec<ReasonCode>,
}

#[derive(Debug, Deserialize)]
pub struct ReasonCode {
    pub code: String,
    pub title: String,
    pub meaning: String,
    pub deprecated: bool,
}

static REGISTRY: OnceLock<ReasonCodeRegistry> = OnceLock::new();

pub fn reason_codes() -> &'static ReasonCodeRegistry {
    REGISTRY.get_or_init(|| {
        serde_json::from_str(include_str!("../../../registry/reason-codes.v1.json"))
            .expect("bundled reason-code registry is valid")
    })
}

pub fn code_title(code: &str) -> Option<&'static str> {
    reason_codes()
        .codes
        .iter()
        .find(|c| c.code == code)
        .map(|c| c.title.as_str())
}
