//! Experimental observations only. Never emits detector-output.v1 or executes evidence.
use chrono::{DateTime, FixedOffset};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

const LIMIT: u64 = 1024 * 1024;

#[derive(Parser)]
#[command(
    about = "Experimental offline repository snapshot diff; observations, not fraud verdicts"
)]
struct Args {
    /// Current caller-supplied snapshot JSON (max 1 MiB)
    current: String,
    #[arg(long)]
    previous: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: String,
    observed_at: DateTime<FixedOffset>,
    source_ref: String,
    provenance: String,
    scope_ref: String,
    repository: String,
    commit_sha: Option<String>,
    /// None means unavailable; Some(empty) means a complete empty inventory.
    files: Option<BTreeMap<String, Artifact>>,
    accounts: Option<BTreeMap<String, Account>>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    sha256: String,
    /// Optional hostile text for fixtures; never interpreted or copied into output.
    text: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Account {
    following: Option<u64>,
    followers: Option<u64>,
    /// Exact caller-normalized public destinations. No URL fetching/normalization.
    destinations: Option<BTreeSet<String>>,
}

#[derive(Debug, Serialize, PartialEq)]
struct Observation {
    axis: &'static str,
    kind: &'static str,
    evidence_ref: String,
    explanation: &'static str,
}

#[derive(Debug, Serialize, PartialEq)]
struct Report {
    schema_version: &'static str,
    rule_version: &'static str,
    current_fingerprint: String,
    previous_fingerprint: Option<String>,
    observed_at: String,
    source_ref: String,
    provenance: String,
    scope_ref: String,
    commit_sha: Option<String>,
    baseline: &'static str,
    technical_assessment: &'static str,
    scanner_status: &'static str,
    observations: Vec<Observation>,
    limitations: &'static str,
}

fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn validate(s: &Snapshot) -> Result<(), &'static str> {
    if s.schema_version != "experimental.github-snapshot.v1"
        || [&s.source_ref, &s.provenance, &s.scope_ref, &s.repository]
            .iter()
            .any(|v| v.trim().is_empty() || v.chars().any(char::is_control))
        || s.commit_sha.as_ref().is_some_and(|v| !hex(v, 40))
    {
        return Err("invalid snapshot metadata");
    }
    if let Some(files) = &s.files {
        for (path, artifact) in files {
            if path.is_empty()
                || path.starts_with('/')
                || path.contains('\\')
                || path.chars().any(char::is_control)
                || path
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == "..")
                || !hex(&artifact.sha256, 64)
            {
                return Err("invalid artifact path or digest");
            }
            if let Some(text) = &artifact.text {
                if digest(text.as_bytes()) != artifact.sha256 {
                    return Err("artifact text does not match digest");
                }
            }
        }
    }
    if s.accounts.as_ref().is_some_and(|accounts| {
        accounts.iter().any(|(id, a)| {
            id.trim().is_empty()
                || id.chars().any(char::is_control)
                || a.destinations.as_ref().is_some_and(|ds| {
                    ds.iter()
                        .any(|d| d.trim().is_empty() || d.chars().any(char::is_control))
                })
        })
    }) {
        return Err("invalid account metadata");
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn fingerprint(s: &Snapshot) -> String {
    // Typed fields in fixed order, sorted maps/sets; canonical for this format,
    // not a general JSON canonicalization standard. Includes text and metadata.
    digest(&serde_json::to_vec(s).expect("typed snapshot serializes"))
}

fn sensitive(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.starts_with(".github/workflows/")
        || path.ends_with(".sh")
        || path.ends_with(".ps1")
        || path.ends_with(".exe")
        || path.ends_with(".dll")
        || path.ends_with(".wasm")
        || path.ends_with(".bin")
        || matches!(
            path.rsplit('/').next().unwrap_or(""),
            "agents.md"
                | "claude.md"
                | "codex.md"
                | "package.json"
                | "cargo.toml"
                | "cargo.lock"
                | "package-lock.json"
                | "build.rs"
                | "makefile"
        )
}

fn compare(current: &Snapshot, previous: Option<&Snapshot>) -> Result<Report, &'static str> {
    validate(current)?;
    if let Some(old) = previous {
        validate(old)?;
        if old.repository != current.repository || old.observed_at > current.observed_at {
            return Err("baseline repository or temporal order mismatch");
        }
    }
    let mut observations = Vec::new();
    let mut add = |axis, kind, evidence_ref, explanation| {
        observations.push(Observation {
            axis,
            kind,
            evidence_ref,
            explanation,
        });
    };
    if let Some(old) = previous {
        match (&old.files, &current.files) {
            (Some(before), Some(after)) => {
                for path in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
                    let change = match (before.get(path), after.get(path)) {
                        (None, Some(_)) => "added",
                        (Some(_), None) => "removed",
                        (Some(a), Some(b)) if a.sha256 != b.sha256 => "modified",
                        _ => continue,
                    };
                    add(
                        "technical_change",
                        if sensitive(path) { "sensitive_surface_changed" } else { "file_changed" },
                        format!("files/{path}:{change}"),
                        "Static inventory change requiring examination; does not establish execution or maliciousness.",
                    );
                }
            }
            _ => add(
                "availability",
                "file_inventory_unavailable",
                "files".into(),
                "Cannot compare incomplete file inventories; no clean result.",
            ),
        }
        if old.commit_sha.is_some()
            && current.commit_sha.is_some()
            && old.commit_sha != current.commit_sha
        {
            add(
                "technical_change",
                "revision_changed",
                "commit_sha".into(),
                "A prior review does not establish the state of this revision.",
            );
        }
    } else {
        add(
            "availability",
            "no_baseline",
            "previous".into(),
            "No temporal conclusion is available.",
        );
    }
    if current.commit_sha.is_none() {
        add(
            "availability",
            "revision_unavailable",
            "commit_sha".into(),
            "Revision attribution unavailable.",
        );
    }
    if current.files.is_none() {
        add(
            "availability",
            "current_files_unavailable",
            "files".into(),
            "No artifact assessment available.",
        );
    }
    if let Some(accounts) = &current.accounts {
        let mut destinations: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (id, account) in accounts {
            if account.following.is_none()
                || account.followers.is_none()
                || account.destinations.is_none()
            {
                add(
                    "availability",
                    "account_fields_unavailable",
                    format!("accounts/{id}"),
                    "Missing public context remains unavailable.",
                );
            }
            if let Some(ds) = &account.destinations {
                for d in ds {
                    destinations.entry(d).or_default().push(id);
                }
            }
        }
        for (destination, ids) in destinations {
            if ids.len() > 1 {
                // Do not echo untrusted URLs; analyst can resolve the input reference.
                add("public_context", "shared_destination", format!("destination_sha256/{}", digest(destination.as_bytes())),
                    "Multiple supplied accounts list the same destination. Possible promotion overlap; no proof of coordination, control or fraud.");
            }
        }
    } else {
        add(
            "availability",
            "accounts_unavailable",
            "accounts".into(),
            "No account context available.",
        );
    }
    Ok(Report {
        schema_version: "experimental.github-diff.v1",
        rule_version: "0.1.0",
        current_fingerprint: fingerprint(current),
        previous_fingerprint: previous.map(fingerprint),
        observed_at: current.observed_at.to_rfc3339(),
        source_ref: current.source_ref.clone(),
        provenance: current.provenance.clone(),
        scope_ref: current.scope_ref.clone(),
        commit_sha: current.commit_sha.clone(),
        baseline: if previous.is_some() { "available" } else { "no_baseline" },
        technical_assessment: "unknown",
        scanner_status: "unavailable_not_run",
        observations,
        limitations: "Caller claims are not independently verified. Path rules are incomplete; no malware scanner, behavior analysis, URL fetch, fraud finding or safety certification. Popularity metrics carry no risk classification. No FPL contract integration.",
    })
}

fn parse(mut reader: impl Read) -> Result<Snapshot, &'static str> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read snapshot")?;
    if bytes.len() as u64 > LIMIT {
        return Err("snapshot exceeds 1 MiB limit");
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| "invalid snapshot JSON")?;
    validate(&snapshot)?;
    Ok(snapshot)
}

fn load(path: &str) -> Result<Snapshot, &'static str> {
    // Caller-selected regular files only. No path from a snapshot is ever opened.
    if !std::fs::metadata(path)
        .map_err(|_| "cannot inspect snapshot")?
        .is_file()
    {
        return Err("snapshot must be a regular file");
    }
    let file = std::fs::File::open(path).map_err(|_| "cannot open snapshot")?;
    if !file
        .metadata()
        .map_err(|_| "cannot inspect snapshot")?
        .is_file()
    {
        return Err("snapshot must be a regular file");
    }
    parse(file)
}

fn main() {
    let args = Args::parse();
    let result = (|| {
        let current = load(&args.current)?;
        let previous = args.previous.as_deref().map(load).transpose()?;
        compare(&current, previous.as_ref())
    })();
    match result {
        Ok(report) if args.json => println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("report serializes")
        ),
        Ok(report) => {
            println!("Experimental static observations — technical assessment: unknown\nBaseline: {}\nScanner: {}", report.baseline, report.scanner_status);
            for observation in report.observations {
                // JSON escaping prevents terminal controls in caller-provided paths.
                println!(
                    "{}: {} — {}",
                    observation.kind,
                    serde_json::to_string(&observation.evidence_ref).expect("string serializes"),
                    observation.explanation
                );
            }
            println!("{}", report.limitations);
        }
        Err(error) => {
            eprintln!("snapshot unavailable: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Snapshot {
        parse(include_bytes!("../../../datasets/experimental/github-before.v1.json").as_slice())
            .unwrap()
    }
    #[test]
    fn installer_change_and_prompt_injection_are_observations_only() {
        let old = fixture();
        let new =
            parse(include_bytes!("../../../datasets/experimental/github-after.v1.json").as_slice())
                .unwrap();
        let report = compare(&new, Some(&old)).unwrap();
        assert_eq!(report, compare(&new, Some(&old)).unwrap());
        assert!(report
            .observations
            .iter()
            .any(|o| o.evidence_ref == "files/install.sh:added"));
        assert!(report
            .observations
            .iter()
            .any(|o| o.evidence_ref == "files/AGENTS.md:added"));
        assert_eq!(report.technical_assessment, "unknown");
        assert_eq!(report.scanner_status, "unavailable_not_run");
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("IGNORE ALL"));
    }
    #[test]
    fn benign_popularity_and_community_links_are_not_fraud() {
        let s = fixture();
        let report = compare(&s, Some(&s)).unwrap();
        assert!(!report
            .observations
            .iter()
            .any(|o| o.axis == "technical_change"));
        assert_eq!(
            report
                .observations
                .iter()
                .filter(|o| o.kind == "shared_destination")
                .count(),
            1
        );
        assert_eq!(report.technical_assessment, "unknown");
    }
    #[test]
    fn no_baseline_and_missing_inventory_remain_unknown() {
        let mut s = fixture();
        s.files = None;
        s.accounts = None;
        s.commit_sha = None;
        let report = compare(&s, None).unwrap();
        assert_eq!(report.baseline, "no_baseline");
        assert_eq!(report.observations.len(), 4);
        assert_eq!(report.technical_assessment, "unknown");
        assert!(compare(&s, Some(&fixture()))
            .unwrap()
            .observations
            .iter()
            .any(|o| o.kind == "file_inventory_unavailable"));
    }
    #[test]
    fn corrupt_oversized_and_misattributed_inputs_fail_without_echoing_data() {
        assert!(parse(b"{secret".as_slice()).is_err());
        assert!(parse(vec![b' '; LIMIT as usize + 1].as_slice()).is_err());
        let mut s = fixture();
        s.repository = "other".into();
        assert!(compare(&s, Some(&fixture())).is_err());
        s = fixture();
        s.schema_version = "future".into();
        assert!(validate(&s).is_err());
        s = fixture();
        s.files.as_mut().unwrap().insert(
            "../install.sh".into(),
            Artifact {
                sha256: "a".repeat(64),
                text: None,
            },
        );
        assert!(validate(&s).is_err());
    }
    #[test]
    fn ordinary_dependency_changes_and_command_discussions_are_not_execution_claims() {
        let old = fixture();
        let mut s = old.clone();
        let text = "Documentation discusses curl | sh; do not run it.";
        s.files.as_mut().unwrap().insert(
            "README.md".into(),
            Artifact {
                sha256: digest(text.as_bytes()),
                text: Some(text.into()),
            },
        );
        s.files.as_mut().unwrap().insert(
            "Cargo.lock".into(),
            Artifact {
                sha256: "b".repeat(64),
                text: None,
            },
        );
        let report = compare(&s, Some(&old)).unwrap();
        assert!(report
            .observations
            .iter()
            .any(|o| o.evidence_ref == "files/README.md:added" && o.kind == "file_changed"));
        assert_eq!(report.technical_assessment, "unknown");
    }
    #[test]
    fn fingerprints_ignore_input_key_order_and_reject_digest_mismatch() {
        let s = fixture();
        let raw = serde_json::to_value(&s).unwrap();
        let reordered: Snapshot = serde_json::from_value(raw).unwrap();
        assert_eq!(fingerprint(&s), fingerprint(&reordered));
        let mut s = s;
        s.files.as_mut().unwrap().insert(
            "install.sh".into(),
            Artifact {
                sha256: "0".repeat(64),
                text: Some("echo demo".into()),
            },
        );
        assert!(validate(&s).is_err());
    }
}
