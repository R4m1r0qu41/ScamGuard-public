//! Allowance-mechanics detector for wallet-decoded transaction intents —
//! the system-weaving point: the CipherLayer Wallet (or any consumer) hands
//! this detector its *already-decoded* intent (transaction-intent.v1
//! instance) and gets contract-conformant findings back. No wallet code is
//! linked; the input is the sibling's published wire format, read
//! tolerantly.

use crate::types::{
    finding, DataSourceClass, DetectorId, DetectorOutput, Provenance, RiskLevel, Subject,
    SubjectKind,
};

pub struct IntentDetector {
    id: DetectorId,
}

impl Default for IntentDetector {
    fn default() -> Self {
        Self {
            id: DetectorId {
                name: "intent-allowance".into(),
                version: "0.1.0".into(),
            },
        }
    }
}

fn provenance() -> Provenance {
    Provenance {
        data_source_class: DataSourceClass::LocalHeuristic,
        dataset_version: None,
        mock: None,
    }
}

impl IntentDetector {
    pub fn id(&self) -> &DetectorId {
        &self.id
    }

    pub fn accepts(&self, kind: SubjectKind) -> bool {
        kind == SubjectKind::TransactionIntent
    }

    /// `subject.value` is the intent id; `intent_json` is the decoded
    /// transaction-intent.v1 instance the consumer already produced.
    pub fn evaluate_intent(
        &self,
        subject: &Subject,
        intent_json: &serde_json::Value,
    ) -> Vec<DetectorOutput> {
        // Accept both the full transaction-intent.v1 shape and the wallet
        // decoder's bare Decoded shape (kind/allowance at top level), so
        // `cipherlayer-cli decode | scam-guard check intent -` works.
        let kind = intent_json["decoded_action"]["kind"]
            .as_str()
            .or_else(|| intent_json["kind"].as_str())
            .unwrap_or("unknown");
        let allowance_kind = intent_json["decoded_action"]["allowance"]["kind"]
            .as_str()
            .or_else(|| intent_json["allowance"]["kind"].as_str());
        let mut out = Vec::new();

        match (kind, allowance_kind) {
            (_, Some("unlimited")) if kind == "set_approval_for_all" => {
                out.push(finding(
                    &self.id,
                    subject,
                    RiskLevel::Critical,
                    0.95,
                    vec!["SG-ALLOW-003", "SG-ALLOW-001"],
                    "Blanket operator approval (setApprovalForAll): the spender gains transfer rights over the entire collection — the primary drainer grant mechanic.".into(),
                    provenance(),
                ));
            }
            (_, Some("unlimited")) => {
                out.push(finding(
                    &self.id,
                    subject,
                    RiskLevel::High,
                    0.9,
                    vec!["SG-ALLOW-001"],
                    "Effectively unbounded token allowance requested; the spender can move the full balance at any later time.".into(),
                    provenance(),
                ));
            }
            ("unknown", _) => {
                out.push(finding(
                    &self.id,
                    subject,
                    RiskLevel::Unknown,
                    0.5,
                    vec!["SG-UNK-001"],
                    "The intent's action could not be decoded; allowance mechanics cannot be assessed. Unknown, not safe.".into(),
                    provenance(),
                ));
            }
            _ => {
                // Known action, bounded (or no) allowance: nothing this
                // detector can honestly flag — and per contract, silence
                // here is not a safety claim.
            }
        }

        // Relative-allowance note: increaseAllowance without on-chain state.
        if kind == "erc20_increase_allowance" {
            out.push(finding(
                &self.id,
                subject,
                RiskLevel::Medium,
                0.6,
                vec!["SG-ALLOW-002", "SG-UNK-001"],
                "increaseAllowance is relative to existing on-chain allowance; the resulting total is not visible in the intent alone.".into(),
                provenance(),
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn subject() -> Subject {
        Subject {
            kind: SubjectKind::TransactionIntent,
            value: "intent-0001".into(),
            chain_id: Some(31337),
        }
    }

    #[test]
    fn unlimited_approval_flags_high() {
        let f = IntentDetector::default().evaluate_intent(
            &subject(),
            &json!({"decoded_action": {"kind": "erc20_approve"}, "allowance": {"kind": "unlimited"}}),
        );
        assert_eq!(f[0].risk_level, RiskLevel::High);
        assert!(f[0].reason_codes.contains(&"SG-ALLOW-001".into()));
    }

    #[test]
    fn blanket_operator_grant_is_critical() {
        let f = IntentDetector::default().evaluate_intent(
            &subject(),
            &json!({"decoded_action": {"kind": "set_approval_for_all"}, "allowance": {"kind": "unlimited"}}),
        );
        assert_eq!(f[0].risk_level, RiskLevel::Critical);
        assert!(f[0].reason_codes.contains(&"SG-ALLOW-003".into()));
    }

    #[test]
    fn undecoded_intent_is_unknown() {
        let f = IntentDetector::default()
            .evaluate_intent(&subject(), &json!({"decoded_action": {"kind": "unknown"}}));
        assert_eq!(f[0].risk_level, RiskLevel::Unknown);
    }

    #[test]
    fn bounded_transfer_is_silent_not_safe() {
        let f = IntentDetector::default().evaluate_intent(
            &subject(),
            &json!({"decoded_action": {"kind": "erc20_transfer"}, "allowance": null}),
        );
        assert!(f.is_empty());
    }
}
