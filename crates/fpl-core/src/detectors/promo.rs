//! Unsolicited crypto promotion/recruitment detector.
//!
//! Everything else in this suite detects *mechanics* (RFC-001 §2: "fraud
//! mechanics, not opinions"). The two base-rate patterns here
//! (`SG-PROMO-001`, `SG-PROMO-002`) are a deliberate, narrow, operator-
//! authorized exception to that rule: they flag airdrop/presale hype and
//! unsolicited crypto-denominated payout offers on topic alone, because
//! real-world prevalence of fraud in these categories is high enough that
//! silence is the wrong default. See `docs/requirements.md` FPL-REQ-016 for
//! the decision record, scope, and the Medium risk ceiling that bounds the
//! false-positive cost against legitimate airdrops and crypto-industry
//! offers. `SG-IMP-002` (false endorsement claim) is not part of that
//! exception — it is an ordinary mechanic: an unverifiable third-party
//! endorsement asserted inside promotional/financial content.

use crate::types::{
    finding, DataSourceClass, DetectorId, DetectorOutput, Provenance, RiskLevel, Subject,
    SubjectKind,
};
use regex::Regex;

struct PromoPattern {
    /// Primary signal. Combined with `context` (if present) via AND to hold
    /// down false positives; used alone when unambiguous on its own.
    primary: Regex,
    context: Option<Regex>,
    code: &'static str,
    risk: RiskLevel,
    confidence: f64,
    label: &'static str,
}

pub struct PromoDetector {
    id: DetectorId,
    patterns: Vec<PromoPattern>,
}

impl Default for PromoDetector {
    fn default() -> Self {
        let re = |p: &str| Regex::new(p).expect("static pattern compiles");
        let patterns = vec![
            // Mechanic: unverifiable endorsement claim inside financial/crypto promo copy.
            PromoPattern {
                primary: re(r"(?i)\b(verified|endorsed|confirmed|certified|backed)\s+by\b"),
                context: Some(re(
                    r"(?i)\b(token|presale|pre-sale|airdrop|crypto|coin|giveaway|invest(ment)?)\b",
                )),
                code: "SG-IMP-002",
                risk: RiskLevel::High,
                confidence: 0.75,
                label: "unverifiable endorsement claim inside promotional/financial content",
            },
            // Base-rate exception: unambiguous claim-funnel phrasing needs no context gate.
            PromoPattern {
                primary: re(
                    r"(?i)claim\s+your\s+(tokens?|airdrop|reward)|connect\s+(your\s+)?wallet\s+to\s+claim",
                ),
                context: None,
                code: "SG-PROMO-001",
                risk: RiskLevel::Medium,
                confidence: 0.6,
                label: "airdrop/presale claim-funnel phrasing",
            },
            // Base-rate exception: airdrop/presale topic, gated on crypto context so
            // Apple AirDrop-style benign usage ("I'll airdrop you the photos") stays silent.
            PromoPattern {
                primary: re(r"(?i)\b(airdrop|pre-?sale)\b"),
                context: Some(re(
                    r"(?i)\b(token|coin|crypto|wallet|nft|\$[A-Z]{2,10}\b)\b",
                )),
                code: "SG-PROMO-001",
                risk: RiskLevel::Medium,
                confidence: 0.55,
                label: "airdrop/presale solicitation",
            },
            // Base-rate exception: recurring crypto-denominated payout offered
            // (not asked for — see SG-ASK-002 for the inverse) in job/staking framing.
            PromoPattern {
                primary: re(r"(?i)\d+(\.\d+)?\s*(sol|eth|btc|usdt|usdc|bnb)\s*(per|/)\s*day"),
                context: Some(re(
                    r"(?i)\b(staking|payout|salary|moderator|part-?time|position|earn|team\s+member)\b",
                )),
                code: "SG-PROMO-002",
                risk: RiskLevel::Medium,
                confidence: 0.5,
                label: "unsolicited crypto-denominated payout/job offer",
            },
        ];
        Self {
            id: DetectorId {
                name: "promo-solicitation".into(),
                version: "0.1.0".into(),
            },
            patterns,
        }
    }
}

impl PromoDetector {
    pub fn id(&self) -> &DetectorId {
        &self.id
    }

    pub fn accepts(&self, kind: SubjectKind) -> bool {
        kind == SubjectKind::MessageText
    }

    pub fn evaluate(&self, subject: &Subject) -> Vec<DetectorOutput> {
        let text = &subject.value;
        let mut out = Vec::new();
        let mut emitted_codes = std::collections::BTreeSet::new();
        for p in &self.patterns {
            if !p.primary.is_match(text) {
                continue;
            }
            if let Some(ctx) = &p.context {
                if !ctx.is_match(text) {
                    continue;
                }
            }
            // A code fires at most once per subject even if two of its
            // patterns both match (e.g. the two SG-PROMO-001 variants).
            if !emitted_codes.insert(p.code) {
                continue;
            }
            out.push(finding(
                &self.id,
                subject,
                p.risk,
                p.confidence,
                vec![p.code],
                format!(
                    "Message matches {}. Treat unsolicited crypto promotions and endorsement claims as scams by default.",
                    p.label
                ),
                Provenance {
                    data_source_class: DataSourceClass::LocalHeuristic,
                    dataset_version: None,
                    mock: None,
                },
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(t: &str) -> Vec<DetectorOutput> {
        PromoDetector::default().evaluate(&Subject::text(t))
    }

    #[test]
    fn fake_celebrity_endorsement_in_presale_copy_is_flagged() {
        let f = eval("X confirms the launch of its platform-native asset. $X TOKEN EXCLUSIVE PRESALE — VERIFIED BY ELON MUSK");
        let codes: Vec<&str> = f
            .iter()
            .flat_map(|x| x.reason_codes.iter())
            .map(String::as_str)
            .collect();
        assert!(codes.contains(&"SG-IMP-002"));
        assert!(codes.contains(&"SG-PROMO-001"));
    }

    #[test]
    fn unsolicited_crypto_payout_job_offer_is_flagged() {
        let f = eval(
            "Payout is 0.8 Sol per day, and there's also a 40% staking option for team members.",
        );
        assert!(f
            .iter()
            .any(|x| x.reason_codes.contains(&"SG-PROMO-002".into())));
        assert!(f.iter().all(|x| x.risk_level == RiskLevel::Medium));
    }

    #[test]
    fn claim_your_tokens_funnel_is_flagged_without_context_gate() {
        let f = eval("Connect your wallet to claim your reward before the deadline.");
        assert!(f
            .iter()
            .any(|x| x.reason_codes.contains(&"SG-PROMO-001".into())));
    }

    #[test]
    fn apple_airdrop_benign_usage_stays_silent() {
        assert!(eval("I'll airdrop you the photos from my phone, one sec.").is_empty());
    }

    #[test]
    fn ordinary_endorsement_outside_promo_context_stays_silent() {
        assert!(eval("The report was independently verified by our legal team.").is_empty());
    }

    #[test]
    fn ordinary_job_compensation_stays_silent() {
        assert!(eval(
            "The interview is scheduled for Tuesday and compensation is paid by bank transfer."
        )
        .is_empty());
    }
}
