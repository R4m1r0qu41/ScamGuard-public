//! Domain Intelligence Engine (concept spec §1, MVP item).
//!
//! Deterministic, offline checks against the local brand-targets dataset:
//! homoglyph/typosquat candidates (SG-DOM-001), punycode-encoded labels
//! (SG-DOM-003), and brand names embedded in unrelated hosts (SG-DOM-004).
//!
//! Honestly out of scope offline: domain age / WHOIS (SG-DOM-002), DNS
//! anomalies, SSL, redirect chains — those need network feeds; when asked
//! about them this detector answers `unknown`, never `low`.

use crate::confusables::{edit_distance_capped, skeleton};
use crate::dataset::BrandTargets;
use crate::types::{
    finding, DataSourceClass, DetectorId, DetectorOutput, Provenance, RiskLevel, Subject,
    SubjectKind,
};

pub struct DomainDetector {
    id: DetectorId,
    targets: &'static BrandTargets,
}

impl Default for DomainDetector {
    fn default() -> Self {
        Self {
            id: DetectorId {
                name: "domain-intelligence".into(),
                version: "0.1.0".into(),
            },
            targets: crate::dataset::brand_targets(),
        }
    }
}

/// Extract host from a URL-ish string; a bare domain passes through.
fn host_of(value: &str) -> String {
    let lowered = value.trim().to_lowercase();
    let v = lowered
        .strip_prefix("https://")
        .or_else(|| lowered.strip_prefix("http://"))
        .unwrap_or(&lowered);
    let v = v.split(['/', '?', '#']).next().unwrap_or(v);
    // Strip userinfo deception (https://apple.com@evil.io/) and ports.
    let v = v.split('@').next_back().unwrap_or(v);
    let v = v.split(':').next().unwrap_or(v);
    v.to_string()
}

/// Registrable domain, MVP heuristic: last two labels, plus a small list of
/// common second-level public suffixes. Documented limitation: no full
/// public-suffix list yet.
fn registrable(host: &str) -> String {
    const SECOND_LEVEL: [&str; 6] = ["co.uk", "com.au", "co.jp", "com.br", "co.in", "com.mx"];
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host.to_string();
    }
    let last_two = labels[labels.len() - 2..].join(".");
    if SECOND_LEVEL.contains(&last_two.as_str()) && labels.len() >= 3 {
        labels[labels.len() - 3..].join(".")
    } else {
        last_two
    }
}

impl DomainDetector {
    pub fn id(&self) -> &DetectorId {
        &self.id
    }

    pub fn accepts(&self, kind: SubjectKind) -> bool {
        matches!(kind, SubjectKind::Domain | SubjectKind::Url)
    }

    fn provenance(&self) -> Provenance {
        Provenance {
            data_source_class: DataSourceClass::LocalDataset,
            dataset_version: Some(self.targets.dataset_version.clone()),
            mock: None,
        }
    }

    pub fn evaluate(&self, subject: &Subject) -> Vec<DetectorOutput> {
        let host = host_of(&subject.value);
        if host.is_empty() || !host.contains('.') {
            return vec![finding(
                &self.id,
                subject,
                RiskLevel::Unknown,
                0.3,
                vec!["SG-UNK-001"],
                format!(
                    "`{}` does not parse as a host; cannot assess.",
                    subject.value
                ),
                self.provenance(),
            )];
        }
        let reg = registrable(&host);
        let mut out = Vec::new();

        // An exact target match is useful positive evidence, but this offline
        // detector cannot establish that a page, redirect chain, DNS answer,
        // or TLS endpoint is trustworthy. Preserve that missing dimension as
        // Unknown so the aggregate can never render this as a clean result.
        if self.targets.is_known_domain(&reg) {
            out.push(finding(
                &self.id,
                subject,
                RiskLevel::Low,
                0.9,
                vec!["SG-UNK-001"],
                format!(
                    "`{reg}` matches known target `{reg}` exactly. Age/DNS/TLS/redirects not assessed offline (unknown, not clean)."
                ),
                self.provenance(),
            ));
            out.push(finding(
                &self.id,
                subject,
                RiskLevel::Unknown,
                0.9,
                vec!["SG-UNK-001"],
                format!(
                    "`{reg}` is an exact target match, but domain age, DNS, TLS, page content, and redirects are unavailable to the offline detector. Unknown, not safe."
                ),
                self.provenance(),
            ));
            return out;
        }

        // Punycode-encoded labels are homoglyph carriers.
        if host.split('.').any(|l| l.starts_with("xn--")) {
            out.push(finding(
                &self.id,
                subject,
                RiskLevel::High,
                0.7,
                vec!["SG-DOM-003"],
                format!("`{host}` contains a punycode-encoded label; review the decoded form before trusting it."),
                self.provenance(),
            ));
        }

        // Lookalike analysis on the registrable domain's name part.
        let name_part = reg.split('.').next().unwrap_or(&reg);
        let folded = skeleton(name_part);
        for brand in &self.targets.brands {
            for known in &brand.domains {
                let known_reg = registrable(known);
                let known_name = known_reg.split('.').next().unwrap_or(&known_reg);
                let known_folded = skeleton(known_name);
                if known_folded.len() < 4 {
                    continue; // short names (x.com) collide too easily for edit-distance games
                }
                let concat_form = known_folded.replace('.', ""); // breezy.hr → breezyhr
                let whole_known = skeleton(&known_reg).replace('.', "");
                if folded == known_folded || folded == whole_known || folded == concat_form {
                    if reg != known_reg {
                        // A byte-identical brand name under a different TLD is a
                        // different claim than a mangled one: legitimate regional
                        // registrations (amazon.co.jp) look exactly like TLD-swap
                        // scams (amazon.xyz), and the offline detector cannot tell
                        // them apart. Honest answer: Medium/unverified, not a
                        // confident High. Any character-level trick (homoglyph
                        // fold, concatenation, edit distance) stays High below.
                        if name_part == known_name && folded == known_folded {
                            out.push(finding(
                                &self.id,
                                subject,
                                RiskLevel::Medium,
                                0.6,
                                vec!["SG-DOM-001"],
                                format!(
                                    "`{reg}` uses the same name as known target `{known_reg}` ({}) under a different TLD; the offline detector cannot verify whether this registration belongs to the brand. Unverified, not confirmed hostile.",
                                    brand.name
                                ),
                                self.provenance(),
                            ));
                        } else {
                            out.push(finding(
                                &self.id,
                                subject,
                                RiskLevel::High,
                                0.9,
                                vec!["SG-DOM-001", "SG-IMP-001"],
                                format!(
                                    "`{reg}` folds to the same skeleton as known target `{known_reg}` ({}) but is a different registration.",
                                    brand.name
                                ),
                                self.provenance(),
                            ));
                        }
                    }
                } else {
                    let cap = if known_folded.len() >= 10 { 2 } else { 1 };
                    let d = edit_distance_capped(&folded, &known_folded, cap);
                    if d <= cap && reg != known_reg {
                        out.push(finding(
                            &self.id,
                            subject,
                            RiskLevel::High,
                            0.75,
                            vec!["SG-DOM-001"],
                            format!(
                                "`{reg}` is edit-distance {d} from known target `{known_reg}` ({}).",
                                brand.name
                            ),
                            self.provenance(),
                        ));
                    }
                }
                // Brand token in a host whose registrable domain is unrelated:
                // metamask.io.evil.com, breezy-careers.com, secure-paypal.xyz.
                let host_folded = skeleton(&host);
                if reg != known_reg
                    && known_folded.len() >= 5
                    && host_folded.contains(&known_folded)
                    && folded != known_folded
                {
                    out.push(finding(
                        &self.id,
                        subject,
                        RiskLevel::High,
                        0.8,
                        vec!["SG-DOM-004", "SG-IMP-001"],
                        format!(
                            "Host `{host}` embeds known brand `{}` but its registrable domain `{reg}` is not the brand's.",
                            brand.name
                        ),
                        self.provenance(),
                    ));
                }
            }
        }

        out.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        out.dedup_by(|a, b| a.reason_codes == b.reason_codes && a.explanation == b.explanation);
        out.truncate(3); // top findings; one domain rarely needs more

        if out.is_empty() {
            out.push(finding(
                &self.id,
                subject,
                RiskLevel::Unknown,
                0.5,
                vec!["SG-UNK-001"],
                format!(
                    "`{reg}` matches no known target and no lookalike pattern in dataset {}; age/DNS/TLS/reputation not assessed offline. Unknown, not safe.",
                    self.targets.dataset_version
                ),
                self.provenance(),
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(d: &str) -> Vec<DetectorOutput> {
        DomainDetector::default().evaluate(&Subject::domain(d))
    }

    #[test]
    fn concept_spec_breezy_examples() {
        // Exact target evidence is Low, paired with Unknown for the network
        // evidence this offline detector cannot collect.
        let known = eval("breezy.hr");
        assert!(known.iter().any(|f| f.risk_level == RiskLevel::Low));
        assert!(known.iter().any(|f| f.risk_level == RiskLevel::Unknown));
        // breezyhr.us = concatenated brand on another TLD → lookalike
        let squat = eval("breezyhr.us");
        assert!(
            squat
                .iter()
                .any(|f| f.reason_codes.contains(&"SG-DOM-001".into())),
            "{squat:?}"
        );
        // breezy-careers.com = brand token in unrelated registration
        let embedded = eval("breezy-careers.com");
        assert!(
            embedded.iter().any(|f| f.risk_level == RiskLevel::High),
            "{embedded:?}"
        );
    }

    #[test]
    fn homoglyph_and_subdomain_deception() {
        // rn → m
        let rn = eval("rnetamask.io");
        assert!(rn
            .iter()
            .any(|f| f.reason_codes.contains(&"SG-DOM-001".into())));
        // brand as subdomain of evil registrable
        let sub = eval("https://metamask.io.wallet-verify.top/login");
        assert!(
            sub.iter()
                .any(|f| f.reason_codes.contains(&"SG-DOM-004".into())),
            "{sub:?}"
        );
        // userinfo deception
        let user = eval("https://apple.com@evil-collect.net/");
        assert!(
            user.iter().all(|f| f.risk_level != RiskLevel::Low),
            "{user:?}"
        );
    }

    #[test]
    fn punycode_is_flagged() {
        let f = eval("xn--pple-43d.com");
        assert!(f
            .iter()
            .any(|x| x.reason_codes.contains(&"SG-DOM-003".into())));
    }

    #[test]
    fn unmatched_domain_is_unknown_never_low() {
        let f = eval("some-random-startup.dev");
        assert_eq!(f[0].risk_level, RiskLevel::Unknown);
        assert!(f[0].reason_codes.contains(&"SG-UNK-001".into()));
    }
}
