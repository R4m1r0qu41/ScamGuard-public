//! Contract types — Rust mirror of `schemas/detector-output.v1.json`.
//! This repo owns the schema, so these types are the reference
//! implementation; a conformance test validates serialized instances
//! against the schema itself.

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: &str = "1.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
    /// First-class: absence of evidence is not evidence of safety.
    /// Consumers must never map this to Low (contract §2).
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Domain,
    Url,
    Address,
    Contract,
    TransactionIntent,
    MessageText,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub kind: SubjectKind,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
}

impl Subject {
    pub fn domain(v: &str) -> Self {
        Subject {
            kind: SubjectKind::Domain,
            value: v.to_string(),
            chain_id: None,
        }
    }
    pub fn url(v: &str) -> Self {
        Subject {
            kind: SubjectKind::Url,
            value: v.to_string(),
            chain_id: None,
        }
    }
    pub fn text(v: &str) -> Self {
        Subject {
            kind: SubjectKind::MessageText,
            value: v.to_string(),
            chain_id: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSourceClass {
    LocalHeuristic,
    LocalDataset,
    RemoteFeed,
    /// Advisory-grade by definition (contract §2). Nothing in the MVP uses it.
    ModelAssisted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub data_source_class: DataSourceClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mock: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorId {
    pub name: String,
    pub version: String,
}

/// One finding from one detector (detector-output.v1 instance).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorOutput {
    pub schema_version: String,
    pub output_id: uuid::Uuid,
    pub detector: DetectorId,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    pub subject: Subject,
    pub risk_level: RiskLevel,
    pub confidence: f64,
    pub reason_codes: Vec<String>,
    pub explanation: String,
    pub provenance: Provenance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<serde_json::Value>,
}

/// Builder used by every detector so no field can be forgotten and every
/// finding carries reasons (explainability is non-negotiable, AGENTS #4).
pub fn finding(
    detector: &DetectorId,
    subject: &Subject,
    risk_level: RiskLevel,
    confidence: f64,
    reason_codes: Vec<&str>,
    explanation: String,
    provenance: Provenance,
) -> DetectorOutput {
    assert!(
        !reason_codes.is_empty(),
        "findings without reason codes are forbidden"
    );
    DetectorOutput {
        schema_version: SCHEMA_VERSION.into(),
        output_id: uuid::Uuid::now_v7(),
        detector: detector.clone(),
        evaluated_at: chrono::Utc::now(),
        subject: subject.clone(),
        risk_level,
        confidence: confidence.clamp(0.0, 1.0),
        reason_codes: reason_codes.into_iter().map(String::from).collect(),
        explanation,
        provenance,
        ext: None,
    }
}
