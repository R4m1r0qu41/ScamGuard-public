//! Scam Guard CLI — the FPL detector suite behind explainable warnings.
//!
//! PROTOTYPE: deterministic offline detectors only. Anything that needs
//! network evidence (domain age, DNS, TLS, sandboxing, reputation feeds)
//! is answered `unknown`, never `low`. Nothing here is a guarantee.

use clap::{Parser, Subcommand};
use fpl_core::engine::{assess, render_warning};
use fpl_core::types::{Subject, SubjectKind};
use fpl_core::Suite;
use std::io::Read;

#[derive(Parser)]
#[command(
    name = "scam-guard",
    version,
    about = "Scam Guard (Fraud Prevention Layer) — explainable, privacy-first fraud checks. Prototype: offline deterministic detectors; unknown is an honest answer."
)]
struct Cli {
    /// Emit the full assessment as JSON instead of the human warning
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check a subject for known fraud mechanics
    Check {
        #[command(subcommand)]
        subject: CheckCmd,
    },
    /// List the Reason Code registry
    Codes,
    /// Show what the detectors can and cannot see (honest capability card)
    Capabilities,
}

#[derive(Subcommand)]
enum CheckCmd {
    /// A domain name (lookalikes, punycode, brand-in-host deception)
    Domain { value: String },
    /// A full URL (host checks incl. userinfo deception)
    Url { value: String },
    /// Message text from a file, or '-' for stdin (command asks,
    /// high-consequence asks, identity impersonation). You are the data
    /// controller: pass only content you are entitled to check.
    Text { file: String },
    /// A wallet-decoded transaction-intent.v1 JSON file (allowance mechanics)
    Intent { file: String },
}

fn read_input(file: &str) -> Result<String, String> {
    if file == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| e.to_string())?;
        Ok(s)
    } else {
        std::fs::read_to_string(file).map_err(|e| format!("cannot read {file}: {e}"))
    }
}

fn main() {
    let cli = Cli::parse();
    let suite = Suite::default();
    let result = match cli.command {
        Command::Codes => {
            for c in &fpl_core::dataset::reason_codes().codes {
                println!(
                    "{:<14} {}{}\n{:14} {}",
                    c.code,
                    c.title,
                    if c.deprecated { "  [DEPRECATED]" } else { "" },
                    "",
                    c.meaning
                );
            }
            return;
        }
        Command::Capabilities => {
            println!("{}", CAPABILITIES.trim());
            return;
        }
        Command::Check { subject } => match subject {
            CheckCmd::Domain { value } => Ok(suite.evaluate(&Subject::domain(&value))),
            CheckCmd::Url { value } => Ok(suite.evaluate(&Subject::url(&value))),
            CheckCmd::Text { file } => {
                read_input(&file).map(|text| suite.evaluate(&Subject::text(&text)))
            }
            CheckCmd::Intent { file } => read_input(&file).and_then(|raw| {
                let intent: serde_json::Value =
                    serde_json::from_str(&raw).map_err(|e| format!("invalid intent JSON: {e}"))?;
                let subject = Subject {
                    kind: SubjectKind::TransactionIntent,
                    value: intent["intent_id"]
                        .as_str()
                        .unwrap_or("unidentified-intent")
                        .to_string(),
                    chain_id: intent["chain_id"].as_u64(),
                };
                Ok(suite.evaluate_intent(&subject, &intent))
            }),
        },
    };

    match result {
        Ok(findings) => {
            let assessment = assess(findings);
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&assessment).expect("assessment serializes")
                );
            } else {
                println!("{}", render_warning(&assessment));
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

const CAPABILITIES: &str = r#"
Scam Guard prototype — honest capability card

CAN check, offline and deterministically:
  · domain/url lookalikes vs a local target dataset (homoglyphs, typosquats,
    brand-in-host deception, punycode labels, userinfo tricks)
  · display-name impersonation of known identities (confusable folding)
  · executable-command structure in text (pipe-to-shell, encoded PowerShell,
    registry edits, terminal-paste instructions, remote-exec primitives)
  · high-consequence asks in text (seed phrase / private key, crypto
    prepayment, gift cards, remote-access installs)
  · allowance mechanics in wallet-decoded transaction intents (unlimited
    approvals, blanket operator grants, relative increases)

CANNOT check (answers `unknown`, never `low`):
  · domain age / WHOIS / DNS / TLS / redirect chains (needs network feeds)
  · link sandboxing and landing-page analysis (needs a sandbox)
  · behavioral signals, account history, graph analysis (needs platform data)
  · avatar/banner image similarity (needs image data)
  · anything about a subject it was never shown

Privacy: this tool collects nothing and calls no network. Every subject is
supplied by you, on your responsibility. Detection targets fraud mechanics,
not opinions (RFC-001 §2).
"#;
