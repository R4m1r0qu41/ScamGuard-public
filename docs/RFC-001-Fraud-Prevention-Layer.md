# RFC-001 --- Fraud Prevention Layer (FPL)

**Title:** Fraud Prevention Layer (FPL): A Privacy-Preserving Platform
Integrity Framework\
**Version:** 0.1 Draft\
**Status:** Draft

## 1. Abstract

Fraud Prevention Layer (FPL) defines a modular platform integrity
framework intended to reduce online fraud through explainable,
risk-based detection while preserving lawful speech, user privacy, and
platform neutrality.

The public-facing implementation is referred to as **Scam Guard**.

## 2. Motivation

FPL addresses phishing, impersonation, fake recruiters, crypto scams,
malware distribution, romance scams, social engineering, account
takeover, and similar abuse.

Rather than moderating opinions or ideology, FPL focuses on identifying
fraud mechanics.

## 3. Design Goals

The framework SHALL:

-   Preserve lawful speech.
-   Minimize privacy intrusion.
-   Operate using metadata whenever feasible.
-   Produce explainable decisions.
-   Support human review.
-   Support modular detectors.
-   Allow incremental deployment.

## 4. Non-Goals

FPL SHALL NOT:

-   Moderate political viewpoints.
-   Rank opinions.
-   Perform generalized surveillance.
-   Replace Trust & Safety teams.

## 5. Terminology

### Detector

Independent module evaluating one fraud category.

### Reason Code

Machine-readable explanation for a detector result.

Examples:

-   LOOKALIKE_DOMAIN
-   IMPERSONATION_AVATAR
-   HIGH_DM_RATE
-   COMMAND_REQUEST
-   FAKE_RECRUITER

### Risk Event

Canonical output produced by a detector.

### Risk Engine

Combines detector outputs into an overall risk score.

## 6. High-Level Architecture

``` text
User Activity
      │
      ▼
Metadata Collection
      │
      ▼
Independent Detection Modules
      │
      ▼
Risk Engine
      │
      ▼
Scam Guard
      │
      ▼
Platform Response
```

## 7. Initial Detection Categories

-   Domain Intelligence
-   Identity Integrity
-   Behavioral Analysis
-   Link Intelligence
-   Command Detection
-   Conversation Protection (opt-in only)

## 8. Privacy Model

### Metadata Only (default)

No message inspection.

### Enhanced Protection

Metadata plus link inspection.

### Maximum Protection

Explicit user opt-in for conversation analysis.

## 9. Explainability

Every decision MUST include:

-   Risk Score
-   Confidence
-   Reason Codes
-   Recommended Action

## 10. Platform Responses

Responses are proportional and may include:

-   Information
-   Warning
-   Additional friction
-   Verification
-   Temporary limitation
-   Manual review
-   Suspension

## 11. Extensibility

Detectors SHALL operate independently.

The Risk Engine SHOULD accept new detectors without architectural
changes.

## 12. Security Considerations

The implementation SHALL assume adversarial behavior, evasion attempts,
model poisoning, coordinated campaigns, and false reporting.

## 13. Future RFCs

-   RFC-002 Risk Scoring
-   RFC-003 Reason Code Registry
-   AI-assisted Detection
-   Graph Analysis
-   Identity Verification
-   Browser Integration
-   Cryptographic Reputation
