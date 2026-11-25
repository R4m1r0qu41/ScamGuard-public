//! High-consequence-ask detection — the shared mechanic behind the concept
//! spec's Recruiter Integrity (§4) and Social Engineering (§5) engines:
//! regardless of the story (job, prize, romance, support), the fraud
//! *mechanics* converge on a small set of asks. Local heuristic on text the
//! caller explicitly provided.

use crate::types::{
    finding, DataSourceClass, DetectorId, DetectorOutput, Provenance, RiskLevel, Subject,
    SubjectKind,
};
use regex::RegexBuilder;

struct AskPattern {
    re: regex::Regex,
    code: &'static str,
    risk: RiskLevel,
    label: &'static str,
}

pub struct AskDetector {
    id: DetectorId,
    patterns: Vec<AskPattern>,
}

impl Default for AskDetector {
    fn default() -> Self {
        let mk = |p: &str| {
            RegexBuilder::new(p)
                .case_insensitive(true)
                .build()
                .expect("static pattern compiles")
        };
        let patterns = vec![
            AskPattern {
                re: mk(
                    r"(seed|recovery|secret)\s+phrase|private\s+key|\b(12|24)\s+words?\b|mnemonic",
                ),
                code: "SG-ASK-001",
                risk: RiskLevel::Critical,
                label: "seed phrase / private key mention in an ask context",
            },
            AskPattern {
                re: mk(
                    r"(pay|send|deposit|transfer)\b[^\n]{0,60}\b(btc|bitcoin|eth|ethereum|usdt|usdc|crypto)[^\n]{0,80}\b(job|position|training|equipment|registration|fee|unlock|release|verify)",
                ),
                code: "SG-ASK-002",
                risk: RiskLevel::High,
                label: "cryptocurrency payment as a precondition",
            },
            AskPattern {
                re: mk(
                    r"(buy|purchase|get|send)[^\n]{0,40}gift\s*cards?|gift\s*card\s*(code|number|pin)",
                ),
                code: "SG-ASK-003",
                risk: RiskLevel::High,
                label: "gift-card payment ask",
            },
            AskPattern {
                re: mk(
                    r"\b(anydesk|teamviewer|screenconnect|ultraviewer|rustdesk)\b|(install|download)[^\n]{0,50}(remote\s+(access|desktop)|screen\s*shar)",
                ),
                code: "SG-ASK-004",
                risk: RiskLevel::High,
                label: "remote-access / screen-sharing software ask",
            },
            AskPattern {
                re: mk(
                    r"(verify|validate|sync|import|connect)[^\n]{0,40}(your\s+)?wallet\b[^\n]{0,60}(phrase|key|immediately|suspended|locked)",
                ),
                code: "SG-ASK-001",
                risk: RiskLevel::Critical,
                label: "wallet-verification pretext",
            },
        ];
        Self {
            id: DetectorId {
                name: "high-consequence-asks".into(),
                version: "0.1.0".into(),
            },
            patterns,
        }
    }
}

impl AskDetector {
    pub fn id(&self) -> &DetectorId {
        &self.id
    }

    pub fn accepts(&self, kind: SubjectKind) -> bool {
        kind == SubjectKind::MessageText
    }

    pub fn evaluate(&self, subject: &Subject) -> Vec<DetectorOutput> {
        let text = &subject.value;
        let mut out = Vec::new();
        for p in &self.patterns {
            if p.re.is_match(text) {
                out.push(finding(
                    &self.id,
                    subject,
                    p.risk,
                    0.8,
                    vec![p.code],
                    format!(
                        "Message contains a high-consequence ask: {}. Legitimate counterparties do not need this.",
                        p.label
                    ),
                    Provenance {
                        data_source_class: DataSourceClass::LocalHeuristic,
                        dataset_version: None,
                        mock: None,
                    },
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(t: &str) -> Vec<DetectorOutput> {
        AskDetector::default().evaluate(&Subject::text(t))
    }

    #[test]
    fn seed_phrase_ask_is_critical() {
        let f = eval(
            "To complete onboarding, verify your wallet by entering your 12 word recovery phrase",
        );
        assert!(f.iter().any(|x| x.risk_level == RiskLevel::Critical));
        assert!(f
            .iter()
            .any(|x| x.reason_codes.contains(&"SG-ASK-001".into())));
    }

    #[test]
    fn job_scam_mechanics_hit() {
        assert!(!eval("You'll need to pay 0.1 ETH registration fee for the position").is_empty());
        assert!(!eval("Please install AnyDesk so IT can configure your laptop").is_empty());
        assert!(!eval("Grandma, buy three Apple gift cards and send me the codes").is_empty());
    }

    #[test]
    fn ordinary_job_talk_is_silent() {
        assert!(eval("The salary is paid monthly by bank transfer, benefits included.").is_empty());
        assert!(eval("We use a wallet-first architecture with a signing pipeline.").is_empty());
    }
}
