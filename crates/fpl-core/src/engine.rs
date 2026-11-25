//! Unified Risk Engine (concept spec "Risk Engine"; RFC-001 §5): combines
//! detector findings into an overall assessment, honoring the same
//! aggregation semantics the contract imposes on consumers — findings are
//! preserved verbatim, `unknown` never launders to `low`, and confident
//! disagreement surfaces as `conflicting`.

use crate::dataset::code_title;
use crate::types::{DetectorOutput, RiskLevel};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallRisk {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
    /// Confident detectors materially disagree; both findings stay visible.
    Conflicting,
}

#[derive(Debug, Serialize)]
pub struct Assessment {
    pub overall: OverallRisk,
    /// RFC-002 §4 numeric score (0–100): a presentation aid derived from and
    /// subordinate to `overall`. `None` for unknown/conflicting — a number
    /// would fake precision where there is none.
    pub score: Option<u8>,
    pub rationale: String,
    /// Findings verbatim — never dropped, never rewritten.
    pub findings: Vec<DetectorOutput>,
    pub recommended_action: String,
}

fn rank(r: RiskLevel) -> u8 {
    match r {
        RiskLevel::Low => 0,
        RiskLevel::Medium => 1,
        RiskLevel::High => 2,
        RiskLevel::Critical => 3,
        RiskLevel::Unknown => 255, // not on the severity axis at all
    }
}

/// RFC-002 §4: base mass per level.
fn base(r: RiskLevel) -> Option<f64> {
    match r {
        RiskLevel::Low => Some(10.0),
        RiskLevel::Medium => Some(40.0),
        RiskLevel::High => Some(70.0),
        RiskLevel::Critical => Some(90.0),
        RiskLevel::Unknown => None,
    }
}

/// RFC-002 §4: deterministic 0–100 score; None off the severity axis.
fn score(overall: OverallRisk, findings: &[DetectorOutput]) -> Option<u8> {
    if matches!(overall, OverallRisk::Unknown | OverallRisk::Conflicting) {
        return None;
    }
    let dominant = findings
        .iter()
        .filter_map(|f| base(f.risk_level).map(|b| b * (0.6 + 0.4 * f.confidence)))
        .fold(f64::NAN, f64::max);
    if dominant.is_nan() {
        return None;
    }
    let n_confident_assessed = findings
        .iter()
        .filter(|f| f.confidence >= 0.7 && f.risk_level != RiskLevel::Unknown)
        .count();
    let corroboration = 5.0 * n_confident_assessed.saturating_sub(1) as f64;
    Some((dominant + corroboration).round().min(100.0) as u8)
}

fn recommended_action(overall: OverallRisk, findings: &[DetectorOutput]) -> String {
    let has = |prefix: &str| {
        findings
            .iter()
            .flat_map(|f| &f.reason_codes)
            .any(|c| c.starts_with(prefix))
    };
    let mut actions: Vec<&str> = Vec::new();
    if has("SG-INJ") {
        actions.push("Do not execute any command or script from this message.");
    }
    if has("SG-ASK-001") {
        actions.push("Never share a seed phrase or private key — no legitimate party needs it.");
    }
    if has("SG-ASK") && !has("SG-ASK-001") {
        actions.push("Do not pay or install anything requested here.");
    }
    if has("SG-DOM") || has("SG-IMP") {
        actions.push("Verify through the official site or channel you already know, not links or names from this context.");
    }
    if has("SG-ALLOW") {
        actions
            .push("Reject or reduce the approval; grant exact amounts to audited spenders only.");
    }
    if has("SG-PROMO") {
        actions.push(
            "Treat unsolicited crypto promotions, endorsement claims, and payout offers as scams by default; do not connect a wallet or send funds.",
        );
    }
    if actions.is_empty() {
        actions.push(match overall {
            OverallRisk::Unknown => {
                "Not enough evidence to assess — treat with the caution you would give any unknown counterparty."
            }
            OverallRisk::Low => "No known-fraud pattern matched; stay alert — this is not a guarantee.",
            _ => "Stop and verify independently before proceeding.",
        });
    }
    actions.join(" ")
}

/// Aggregate findings for one subject.
pub fn assess(findings: Vec<DetectorOutput>) -> Assessment {
    if findings.is_empty() {
        return Assessment {
            overall: OverallRisk::Unknown,
            score: None,
            rationale:
                "No detector produced a finding; absence of evidence is not evidence of safety."
                    .into(),
            recommended_action: recommended_action(OverallRisk::Unknown, &[]),
            findings,
        };
    }

    let confident: Vec<&DetectorOutput> = findings.iter().filter(|f| f.confidence >= 0.7).collect();

    // Conflict: confident detectors at opposite ends of the severity axis.
    let conflict = {
        let assessed: Vec<u8> = confident
            .iter()
            .filter(|f| f.risk_level != RiskLevel::Unknown)
            .map(|f| rank(f.risk_level))
            .collect();
        match (assessed.iter().min(), assessed.iter().max()) {
            (Some(&min), Some(&max)) => min == 0 && max >= 2,
            _ => false,
        }
    };

    let max_assessed = findings
        .iter()
        .filter(|f| f.risk_level != RiskLevel::Unknown)
        .map(|f| rank(f.risk_level))
        .max();
    let has_unknown = findings.iter().any(|f| f.risk_level == RiskLevel::Unknown);

    let overall = if conflict {
        OverallRisk::Conflicting
    } else {
        match max_assessed {
            Some(3) => OverallRisk::Critical,
            Some(2) => OverallRisk::High,
            Some(1) => OverallRisk::Medium,
            Some(_) if !has_unknown => OverallRisk::Low,
            // Only-low + unknown stays unknown-tinged: report Unknown.
            Some(_) => OverallRisk::Unknown,
            None => OverallRisk::Unknown,
        }
    };

    let mut cited: Vec<String> = findings
        .iter()
        .flat_map(|f| f.reason_codes.iter())
        .map(|c| match code_title(c) {
            Some(t) => format!("{c} ({t})"),
            None => c.clone(),
        })
        .collect();
    cited.sort();
    cited.dedup();

    Assessment {
        overall,
        score: score(overall, &findings),
        rationale: format!(
            "{} finding(s) from {} detector(s): {}",
            findings.len(),
            {
                let mut d: Vec<&str> = findings.iter().map(|f| f.detector.name.as_str()).collect();
                d.sort();
                d.dedup();
                d.len()
            },
            cited.join(", ")
        ),
        recommended_action: recommended_action(overall, &findings),
        findings,
    }
}

/// Render the explainable warning exactly in the concept spec's shape.
pub fn render_warning(a: &Assessment) -> String {
    let mut s = String::new();
    s.push_str("Scam Guard Warning\n\n");
    match a.score {
        Some(n) => s.push_str(&format!(
            "Risk: {:?} (score {n}/100)\n\nReasons\n",
            a.overall
        )),
        None => s.push_str(&format!(
            "Risk: {:?} (no score: not on the severity axis)\n\nReasons\n",
            a.overall
        )),
    }
    let mut seen = std::collections::BTreeSet::new();
    for f in &a.findings {
        for c in &f.reason_codes {
            if seen.insert(c.clone()) {
                let title = code_title(c).unwrap_or("(unregistered code)");
                s.push_str(&format!("  ✓ {title} [{c}]\n"));
            }
        }
    }
    s.push_str("\nRecommended Action\n");
    s.push_str(&format!("  {}\n", a.recommended_action));
    s.push_str("\nDetails\n");
    for f in &a.findings {
        s.push_str(&format!(
            "  · {:?} (confidence {:.2}) — {} [{} v{}, {:?}{}]\n",
            f.risk_level,
            f.confidence,
            f.explanation,
            f.detector.name,
            f.detector.version,
            f.provenance.data_source_class,
            f.provenance
                .dataset_version
                .as_deref()
                .map(|v| format!(", dataset {v}"))
                .unwrap_or_default(),
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{finding, DataSourceClass, DetectorId, Provenance, Subject};

    fn f(risk: RiskLevel, conf: f64, code: &str) -> DetectorOutput {
        finding(
            &DetectorId {
                name: "t".into(),
                version: "0".into(),
            },
            &Subject::domain("example.com"),
            risk,
            conf,
            vec![code],
            "test".into(),
            Provenance {
                data_source_class: DataSourceClass::LocalHeuristic,
                dataset_version: None,
                mock: None,
            },
        )
    }

    #[test]
    fn unknown_never_launders_to_low() {
        let a = assess(vec![
            f(RiskLevel::Low, 0.9, "SG-UNK-001"),
            f(RiskLevel::Unknown, 0.5, "SG-UNK-001"),
        ]);
        assert_eq!(a.overall, OverallRisk::Unknown);
    }

    #[test]
    fn max_severity_wins() {
        let a = assess(vec![
            f(RiskLevel::Medium, 0.8, "SG-DOM-001"),
            f(RiskLevel::Critical, 0.9, "SG-ASK-001"),
        ]);
        assert_eq!(a.overall, OverallRisk::Critical);
    }

    #[test]
    fn confident_disagreement_is_conflicting_with_both_visible() {
        let a = assess(vec![
            f(RiskLevel::Low, 0.9, "SG-UNK-001"),
            f(RiskLevel::High, 0.9, "SG-DOM-001"),
        ]);
        assert_eq!(a.overall, OverallRisk::Conflicting);
        assert_eq!(a.findings.len(), 2);
    }

    #[test]
    fn empty_is_unknown_and_says_so() {
        let a = assess(vec![]);
        assert_eq!(a.overall, OverallRisk::Unknown);
        assert!(a.rationale.contains("absence of evidence"));
    }

    #[test]
    fn score_follows_rfc002() {
        // Single high @0.9 → 70 * (0.6+0.36) = 67.2 → 67, no corroboration.
        let a = assess(vec![f(RiskLevel::High, 0.9, "SG-DOM-001")]);
        assert_eq!(a.score, Some(67));
        // Corroborated: +5 for the second confident assessed finding.
        let a = assess(vec![
            f(RiskLevel::High, 0.9, "SG-DOM-001"),
            f(RiskLevel::Medium, 0.8, "SG-IMP-001"),
        ]);
        assert_eq!(a.score, Some(72));
        // Unknown and conflicting carry no number.
        assert_eq!(
            assess(vec![f(RiskLevel::Unknown, 0.5, "SG-UNK-001")]).score,
            None
        );
        let c = assess(vec![
            f(RiskLevel::Low, 0.9, "SG-UNK-001"),
            f(RiskLevel::High, 0.9, "SG-DOM-001"),
        ]);
        assert_eq!(c.overall, OverallRisk::Conflicting);
        assert_eq!(c.score, None);
        // Bounded at 100.
        let many: Vec<_> = (0..10)
            .map(|_| f(RiskLevel::Critical, 1.0, "SG-ASK-001"))
            .collect();
        assert_eq!(assess(many).score, Some(100));
    }

    #[test]
    fn warning_render_carries_reasons_and_provenance() {
        let a = assess(vec![f(RiskLevel::High, 0.9, "SG-DOM-001")]);
        let w = render_warning(&a);
        assert!(w.contains("Scam Guard Warning"));
        assert!(w.contains("SG-DOM-001"));
        assert!(w.contains("Lookalike domain"));
        assert!(w.contains("Recommended Action"));
    }
}
