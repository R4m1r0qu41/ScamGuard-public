use std::process::Command;

fn snapshot_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_scam-guard-snapshot"))
}

#[test]
fn snapshot_cli_supports_both_outputs_and_honest_missing_baseline() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../datasets/experimental");
    let current = root.join("github-after.v1.json");
    let previous = root.join("github-before.v1.json");
    let output = snapshot_bin()
        .arg(&current)
        .arg("--previous")
        .arg(previous)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["technical_assessment"], "unknown");
    assert_eq!(report["baseline"], "available");
    assert!(report["observations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|o| o["evidence_ref"] == "files/install.sh:added"));
    let human = snapshot_bin().arg(&current).output().unwrap();
    assert!(human.status.success());
    assert!(String::from_utf8(human.stdout)
        .unwrap()
        .contains("no_baseline"));
}

#[test]
fn malformed_input_is_unavailability_with_no_payload_in_diagnostics() {
    // Source file is deliberately invalid JSON; no temporary private data needed.
    let output = snapshot_bin()
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/snapshot_cli.rs"
        ))
        .arg("--json")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(diagnostic.contains("snapshot unavailable: invalid snapshot JSON"));
    assert!(!diagnostic.contains("use std"));
}
