//! Identity Integrity Engine (concept spec §2), first pass: display-name /
//! handle impersonation of known targets via confusable folding — the
//! "Michael SayIor" mechanic. Subject kind is message_text (the name string
//! the caller wants checked); avatar/banner similarity needs image data and
//! is out of scope offline.

use crate::confusables::{edit_distance_capped, skeleton};
use crate::dataset::BrandTargets;
use crate::types::{
    finding, DataSourceClass, DetectorId, DetectorOutput, Provenance, RiskLevel, Subject,
    SubjectKind,
};

pub struct IdentityDetector {
    id: DetectorId,
    targets: &'static BrandTargets,
}

impl Default for IdentityDetector {
    fn default() -> Self {
        Self {
            id: DetectorId {
                name: "identity-integrity".into(),
                version: "0.1.0".into(),
            },
            targets: crate::dataset::brand_targets(),
        }
    }
}

impl IdentityDetector {
    pub fn id(&self) -> &DetectorId {
        &self.id
    }

    pub fn accepts(&self, kind: SubjectKind) -> bool {
        kind == SubjectKind::MessageText
    }

    fn provenance(&self) -> Provenance {
        Provenance {
            data_source_class: DataSourceClass::LocalDataset,
            dataset_version: Some(self.targets.dataset_version.clone()),
            mock: None,
        }
    }

    pub fn evaluate(&self, subject: &Subject) -> Vec<DetectorOutput> {
        let candidate = subject.value.trim();
        if candidate.is_empty() || candidate.len() > 120 {
            return Vec::new(); // not a name-shaped input; other detectors handle prose
        }
        let folded = skeleton(candidate);
        let mut out = Vec::new();

        let mut names: Vec<&str> = self.targets.persons.iter().map(String::as_str).collect();
        let brand_names: Vec<&str> = self
            .targets
            .brands
            .iter()
            .map(|b| b.name.as_str())
            .collect();
        names.extend(brand_names);

        for name in names {
            let known = skeleton(name);
            if known.len() < 4 {
                continue;
            }
            if folded == known && candidate.to_lowercase() != name.to_lowercase() {
                out.push(finding(
                    &self.id,
                    subject,
                    RiskLevel::High,
                    0.9,
                    vec!["SG-IMP-001"],
                    format!(
                        "`{candidate}` folds to the same skeleton as known identity `{name}` but is written differently — classic homoglyph impersonation."
                    ),
                    self.provenance(),
                ));
            } else if folded != known
                && edit_distance_capped(&folded, &known, 1) == 1
                && known.len() >= 8
            {
                out.push(finding(
                    &self.id,
                    subject,
                    RiskLevel::Medium,
                    0.6,
                    vec!["SG-IMP-001"],
                    format!("`{candidate}` is one edit from known identity `{name}`."),
                    self.provenance(),
                ));
            }
        }
        out.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        out.truncate(2);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(t: &str) -> Vec<DetectorOutput> {
        IdentityDetector::default().evaluate(&Subject::text(t))
    }

    #[test]
    fn concept_spec_saylor_example() {
        // "Michael SayIor" with uppercase I — must flag, high confidence.
        let f = eval("Michael SayIor");
        assert!(!f.is_empty());
        assert_eq!(f[0].risk_level, RiskLevel::High);
        assert!(f[0].reason_codes.contains(&"SG-IMP-001".into()));
    }

    #[test]
    fn the_real_name_is_not_flagged_as_impersonating_itself() {
        assert!(eval("Michael Saylor").is_empty());
    }

    #[test]
    fn unrelated_names_are_silent() {
        assert!(eval("Jordan Ramirez").is_empty());
    }
}
