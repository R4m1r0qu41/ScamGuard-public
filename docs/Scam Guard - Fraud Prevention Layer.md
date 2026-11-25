# Fraud Prevention Layer (FPL)
## Public Product: Scam Guard

**Version:** 0.1 (Concept Specification)
**Status:** MVP Architecture
**Author:** CipherLayer
**Date:** 2026-07-01

---

# Purpose

Fraud Prevention Layer (FPL) is a platform-integrated fraud detection and prevention framework designed to significantly reduce online scams while preserving:

- Freedom of expression
- User privacy
- Platform neutrality
- Legitimate communication

The public-facing product is called **Scam Guard**.

The objective is **not censorship**.

The objective is to identify and interrupt known fraud techniques before users become victims.

---

# Design Philosophy

FPL should:

- Detect behavior, not opinions.
- Detect fraud mechanics, not ideology.
- Apply friction proportional to risk.
- Preserve privacy by default.
- Be transparent and explainable.
- Allow user control whenever practical.
- Never silently read private conversations without explicit opt-in.

---

# Core Principles

## Principle 1

Protect users without limiting lawful speech.

---

## Principle 2

Metadata is preferred over message content.

Only inspect content when:

- user explicitly opts in

or

- platform safety policy requires it.

---

## Principle 3

Everything produces explainable reasons.

No opaque AI-only decisions.

Every warning should include:

- Risk Score
- Reason Codes
- Confidence

Example

Risk: High

Reasons

✓ Lookalike domain

✓ Impersonation indicators

✓ Suspicious account history

---

# Overall Architecture

FPL consists of multiple independent detection engines.

These engines feed a unified Risk Engine.

```
                +---------------------+
                | User Interaction    |
                +----------+----------+
                           |
                           |
                +----------v----------+
                | Metadata Pipeline   |
                +----------+----------+
                           |
      ----------------------------------------------
      |        |        |        |        |         |
      v        v        v        v        v         v

 Domain   Identity   Behavior   Links   Network   Reputation
 Engine    Engine     Engine    Engine   Engine      Engine

      ----------------------------------------------
                           |
                           v

                 Unified Risk Engine

                           |
          ----------------------------------

          Low
          Medium
          High
          Critical

                           |
                           v

                Scam Guard Response Layer

```

---

# Detection Modules

## 1. Domain Intelligence Engine

Purpose

Detect

- phishing domains
- typo domains
- fake recruiters
- fake exchanges
- fake wallets

Checks

- domain age

- WHOIS

- DNS anomalies

- SSL certificate

- redirect chain

- brand similarity

- homoglyph attacks

Examples

breezy.hr

vs

breezyhr.us

vs

breezy-careers.com

---

## 2. Identity Integrity Engine

Purpose

Detect impersonation.

Checks

- Display name similarity

- Username similarity

- Avatar similarity

- Banner similarity

- Claimed employer

- Claimed website

- Mentioned official account

Examples

Michael Saylor

Michael SayIor

(using uppercase I)

---

## 3. Behavioral Engine

Purpose

Detect fraud behavior.

Signals include

High DM rate

New account

Mass follows

Mass unfollows

Many outbound links

Repeated first messages

Repeated templates

Large block rate

Many reports

Multiple bans

Rapid account recreation

---

## 4. Recruiter Integrity Engine

Purpose

Detect fake recruiters.

Signals

Company mismatch

Recruiter history inconsistent

Random unrelated posting history

Fake ATS

Assessment domains

Requests to install software

Requests to run terminal commands

Requests for private keys

Requests for seed phrases

Requests for crypto payment

---

## 5. Social Engineering Engine

Purpose

Detect common manipulation patterns.

Examples

Urgency

Scarcity

Authority abuse

Celebrity impersonation

Investment guarantees

Employment pressure

Romance escalation

Gift card requests

Crypto wallet requests

---

## 6. Command Detection Engine

Purpose

Detect executable instructions.

Examples

PowerShell

CMD

Bash

Terminal

Registry edits

Encoded PowerShell

Certutil

MSHTA

Curl

Wget

SSH

Remote Desktop

This module should detect command structure rather than semantic meaning.

---

## 7. Link Reputation Engine

Purpose

Sandbox URLs.

Check

redirects

downloads

browser fingerprinting

credential harvesting

known malware

landing page changes

---

## 8. Conversation Risk Engine

Default mode

Metadata only.

Optional mode

User opt-in.

Capabilities

Detect

wallet requests

bank requests

gift card scams

romance scams

pig butchering

investment scams

crypto scams

job scams

fake support

---

## 9. AI Layer (Future)

AI is NOT required for MVP.

Future responsibilities

Behavior clustering

Novel scam detection

Natural language explanation

False positive reduction

Continuous learning

---

# Risk Engine

Each detector produces

Score

Confidence

Reason Codes

Example

```
Domain Engine

Score: 85

Reason

LOOKALIKE_DOMAIN

Identity Engine

Score: 90

Reason

IMPERSONATION_AVATAR

Behavior Engine

Score: 45

Reason

HIGH_DM_RATE

Overall

Risk = HIGH
```

---

# Response Layer

Possible actions

Inform only

Yellow warning

Orange warning

Red warning

Require confirmation

Disable previews

Slow outbound messaging

Temporary restrictions

Mandatory verification

Manual review

Account suspension

---

# User Privacy Modes

## Mode A

Privacy Maximum

Metadata only.

No message reading.

---

## Mode B

Enhanced Protection

Metadata

+

Link scanning

+

Command detection

---

## Mode C

Maximum Protection

Explicit opt-in.

Message scanning

Credential detection

Fraud coaching

---

# Mandatory Platform Protection

Some protections cannot be disabled.

Examples

Known malware

Known phishing

Known impersonation

Mass scams

Account takeover

Bot farms

---

# Enhanced Protection Triggers

Cannot be opted out.

Examples

Account age

IP reputation

Device reputation

Bot probability

Mass messaging

Mass reporting

Repeated suspensions

High-risk financial behavior

---

# Explainability

Every warning should explain WHY.

Example

Scam Guard Warning

Risk: High

Reasons

• Lookalike domain

• Fake recruiter indicators

• Suspicious command request

• Newly created account

Recommended Action

Do not execute commands.

Verify through official company channels.

---

# Platform Goals

Increase trust.

Reduce scams.

Reduce account takeovers.

Reduce phishing.

Reduce impersonation.

Reduce fake recruiters.

Reduce crypto fraud.

Reduce investment scams.

Reduce romance scams.

Reduce malware.

---

# Non Goals

Not political moderation.

Not censorship.

Not content ranking.

Not shadow banning.

Not surveillance.

Not advertising optimization.

---

# MVP

Version 1

Implement

✓ Domain Intelligence

✓ Identity Integrity

✓ Recruiter Detection

✓ Link Reputation

✓ Risk Engine

✓ Explainable Warnings

Skip

AI

Deep NLP

Large-scale graph analysis

Behavior prediction

---

# Long-Term Vision

Fraud Prevention Layer becomes a reusable trust infrastructure that can be integrated into:

- Social media
- Professional networking platforms
- Messaging platforms
- Crypto wallets
- Crypto exchanges
- Browser extensions
- Email clients
- Enterprise collaboration platforms

The system functions as a modular fraud detection framework that combines metadata analysis, behavioral signals, explainable risk scoring, and optional AI assistance to reduce online fraud while preserving user privacy and freedom of expression.