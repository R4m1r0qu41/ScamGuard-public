# RFC-006 — Privacy and Consent Model

**Version:** 0.1 · **Status:** Draft for operator review · **Date:** 2026-07-18 · Extends RFC-001 §8, ADR-001, and `FPL-REQ-012`

## 1. Purpose

Scam Guard needs enough visibility to detect social-engineering campaigns without becoming a general-purpose surveillance or censorship system. This RFC defines which fraud-protection signals may be processed by default, which enhanced capabilities require affirmative user consent, which narrowly scoped platform-integrity controls apply to all accounts, and how evidence moves from a weak trigger to a higher-confidence assessment.

This is a product and architecture draft, not a conclusion about the legal basis available in every jurisdiction. Deployment-specific terms, notices, retention periods, and mandatory processing require privacy, security, and legal review.

### 1.1 Existing authority and proposed clarification

Accepted ADR-001 already permits conversation-content processing through explicit user opt-in or a narrowly defined platform-safety exception. Draft RFC-001 describes Mode B as metadata plus link inspection and Mode C as explicit conversation analysis, while the founding concept also assigns command detection to Mode B. Because command detection requires some content visibility, the current Mode B boundary is internally ambiguous.

This draft proposes resolving that ambiguity by giving Mode B explicit-consent, interaction-bounded content access and reserving broader conversation context for Mode C. Until RFC-006 is accepted, this proposal creates no new processing authority and ADR-001 remains controlling.

## 2. Governing principles

1. **Fraud mechanics, not opinions.** Detection is restricted to explainable mechanics of phishing, impersonation, malware, account takeover, coordinated fraud, and social engineering. It MUST NOT rank political views, lawful speech, ideology, or ordinary sentiment.
2. **Least-intrusive useful signal first.** Metadata, behavioral patterns, graph relationships, public profiles, and public links are evaluated before private conversation content.
3. **Purpose limitation.** Data obtained for fraud protection MUST NOT be reused for advertising, generalized content moderation, employee monitoring, model training, or unrelated profiling.
4. **Layered confidence.** A keyword, burst, repeated message, new account, location mismatch, or public-profile inconsistency is a routing signal, not proof of fraud. Additional independent evidence raises or lowers confidence.
5. **Explainability and unknown.** Every material result carries confidence, reason codes, provenance, and the evidence classes used. Missing evidence remains `unknown`; silence is never represented as proof of safety.
6. **Proportional response.** Weak evidence produces observation or friction. High-impact restrictions require stronger corroboration and, where practical, human review and appeal.
7. **Background by default, visible when material.** Ordinary legitimate use should not be interrupted. Users receive notices when Scam Guard needs consent, recommends protection, or causes a material intervention.

## 3. Two distinct authority paths

### 3.1 User-selected enhanced protection

Enhanced access to a protected user's chats, sent messages, downloads, links, or selected files requires affirmative, informed consent. Consent MUST identify:

- the enabled protection mode and product;
- the data classes inspected;
- whether processing occurs locally, by the platform, or by a named service;
- the purpose and detector families involved;
- the retention behavior;
- the duration and revocation path; and
- whether automated outbound activity is included.

Consent MUST be recorded as a versioned receipt. A materially broader purpose, data class, or retention rule requires renewed consent. Revocation stops future optional processing and deletes optional retained raw content according to the approved retention schedule; it does not erase already completed security actions or evidence that must be retained under a separately approved obligation.

### 3.2 Mandatory platform-integrity processing

Attackers cannot opt out of controls that protect the service and other users. A platform MAY require narrowly scoped security processing as a condition of using the service, with clear notice and product-specific policy. This mandatory path is not presented as optional consent.

Mandatory processing is limited to:

- account age and creation velocity;
- authentication, device, IP, and account-takeover signals;
- messaging rate, recipient fan-out, burst behavior, and repeated-message patterns;
- declared or detected automated operation;
- known-malware, known-phishing, known-impersonation, and malicious-link indicators;
- public profile, public post, public link, and other legitimately available public context; and
- narrowly defined platform-safety exceptions approved in the product's policy.

Mandatory controls MUST NOT become blanket private-message review. Escalation into private content requires either the user's enhanced-protection consent, the sender's automation policy, or a separately approved, documented platform-safety exception with narrow purpose, access controls, and reviewability.

## 4. Protection modes

| Mode | Authority | Data and capabilities | Default behavior |
|---|---|---|---|
| A — Privacy Maximum | Baseline platform-integrity policy | Metadata, behavioral patterns, graph signals, public profiles/posts, public links, known-threat indicators | No private-message reading. Available to every account and includes mandatory service-integrity controls. |
| B — Enhanced Protection | Affirmative protected-user consent | Mode A plus link inspection, click-time sandboxing, command/ask detection, bounded chat and sent-message inspection, downloads, and explicitly selected files | Optional for ordinary users. Scope is limited to the protected interactions and products named in the consent receipt. |
| C — Maximum Protection | Separate explicit opt-in | Mode B plus broader conversation context, credential exposure detection, fraud coaching, and longer context windows needed for campaign analysis | Off by default. Requires the clearest notice, shortest practical raw-content retention, and an easy revocation path. |
| Automation / Operator tier | Mandatory declaration and service policy for bots, agents, MCP clients, scrapers, marketing tools, developer tools, and other automated senders | Outbound message preflight, recipient fan-out, repetition, link and file checks, rate controls, and campaign-level evidence | Automated outbound operations MUST accept the stronger screening tier before sending at scale. |

Modes describe processing authority, not a promise that every detector exists. Capabilities remain honest and versioned through the detector contract and capability output.

## 5. Detection and escalation pipeline

### 5.1 Structural and behavioral triggers

The first pass evaluates low-content or content-independent signals such as:

- new-account age combined with immediate high-volume outreach;
- simultaneous or rapid messages to many recipients;
- substantially repeated outbound messages;
- abrupt changes in device, location, network, or account behavior;
- links, downloads, payment instructions, credential requests, or remote-access asks; and
- declared or inferred automated operation.

Where feasible, platforms SHOULD compare repetition and fan-out using privacy-preserving hashes, sketches, secure aggregation, or proof systems rather than centralizing raw message bodies. Cryptographic or zero-knowledge designs are optional research directions until a concrete protocol and threat model are separately accepted; this RFC does not claim that such a system exists today.

### 5.2 Product-specific concept routing

Terms and concepts such as deposits, support, transfers, money, payments, meetings, recruiting, acquisitions, credentials, and remote access MAY route an interaction to further review. Each product owns a versioned context profile because normal language differs materially between products: “meeting” is routine on LinkedIn or in a Teams/Zoom workflow, while a transfer request may be unusual in another context.

A concept hit alone MUST NOT produce an adverse account action. It identifies which contextual detectors should run and contributes only the confidence supported by its surrounding evidence.

### 5.3 Public contextual analysis

Scam Guard MAY compare the observed activity with legitimately available public context without requiring enhanced-content consent. Relevant context includes:

- public posts and public links;
- claimed location and publicly stated location;
- public work history and role claims;
- profile creation date and visible account history;
- public employer, recruiter, project, or brand associations; and
- inconsistencies between the public persona and the activity being performed.

For example, a public job-seeking profile associated with a call center in one location while privately representing a major venture or crypto firm is a contextual inconsistency worth corroborating. It is not, by itself, proof of fraud. Public-data use remains subject to source terms, accuracy controls, minimization, and the same no-censorship purpose boundary.

### 5.4 Contextual content analysis

When the applicable authority permits content access, contextual analysis combines conversation sequence, asks, links, files, identity claims, public context, and behavioral evidence. Independent corroboration can raise confidence; benign context can lower it. Model-assisted analysis, when introduced, remains advisory, labeled in provenance, and cannot be the sole basis for a high-impact action.

### 5.5 Link and download preflight

Public reputation and hostname checks SHOULD run before navigation where possible. When a user clicks a link under Mode B or C, or when platform-integrity policy identifies a known-threat indicator, the destination is opened first in an isolated sandbox that checks at minimum:

- HTTPS and certificate sanity;
- redirects and final destination;
- lookalike, punycode, subdomain, and brand-target patterns;
- known phishing or malware reputation;
- unexpected downloads, executable content, and credential collection; and
- basic landing-page consistency with the represented organization.

The sandbox MUST NOT receive the user's session cookies, wallet secrets, credentials, local files, or unrestricted internal-network access. Fetching controls must address SSRF, redirect abuse, archive bombs, and malicious file formats. A failed sandbox or missing network evidence produces `unknown` and an appropriate warning, never an unearned clean result.

## 6. Automation and outbound operations

Bots, MCP clients, scrapers, marketing systems, developer tools, metrics tools, and other automated operators can create legitimate high-volume patterns that resemble abuse. They MUST declare their automated role and accept the Automation / Operator tier before sending messages or links at scale.

The tier SHOULD provide documented quotas, preflight APIs, batch-safe checks, reason-coded rejections, and an appeal or verification path so legitimate operators can correct configuration without guessing. Undeclared automation, recipient fan-out, repeated content, newly created accounts, and high-risk asks increase scrutiny. The goal is low-friction operation for well-intentioned automation and materially higher cost for fraud campaigns.

## 7. Data handling and provenance

### 7.1 Minimize raw content

Raw private content SHOULD be processed locally or ephemerally where the detector can operate that way. Systems SHOULD retain structured findings, reason codes, confidence, policy decisions, and privacy-safe references instead of raw chats or files. Any retained raw evidence needs an approved purpose, access boundary, encryption, deletion schedule, and audit trail.

The current `detector-output.v1` contract echoes `subject.value`, which can contain raw `message_text`. Consumers MUST treat that field as sensitive and MUST NOT persist it by default. A privacy-preserving subject reference, redaction profile, or new versioned wire contract is required before claiming durable content-minimized storage; RFC-006 does not silently change the published v1 schema.

### 7.2 Required provenance

Every content-capable or platform-integrity evaluation SHOULD record:

- product and protection mode;
- authority path: consent receipt, automation policy, or named safety exception;
- consent/policy version and timestamp;
- data classes actually examined;
- detector and dataset versions;
- local, platform, remote-feed, or model-assisted processing class;
- retention class; and
- resulting reason codes, confidence, and response.

Access to consent receipts and raw evidence is itself auditable. Operators MUST NOT be able to enable broader content access silently.

## 8. Responses, review, and user experience

- Low-confidence or single-signal results inform, queue, or add reversible friction.
- Multiple independent signals may increase warning strength or require verification.
- Account limitation, suspension, or comparable high-impact action requires product-specific policy, explainable evidence, and a review/appeal path.
- Known malware, phishing, impersonation, account takeover, bot farms, or mass scams may trigger mandatory protection, but the exact exception and response must be enumerated in the product profile.
- A protected user is notified when an intervention materially changes their action, unless notice would create a documented security risk.
- A sender or operator receives reason-coded guidance sufficient to correct legitimate behavior without exposing detector internals that would enable trivial evasion.

## 9. Product profiles

Each integrating product MUST publish a reviewed profile that defines:

- which modes it supports;
- its normal and suspicious behavior baselines;
- its contextual concept categories and locales;
- its automation declaration and rate policy;
- its platform-safety exceptions;
- its link/download sandbox binding;
- thresholds and response mapping;
- raw-content and finding retention periods; and
- consent, revocation, review, and appeal surfaces.

Product profiles may tune context and thresholds but cannot weaken the governing principles, invent unregistered reason codes, treat `unknown` as safe, or repurpose fraud-protection data.

## 10. Security and abuse considerations

Implementations must account for evasion, coordinated low-and-slow campaigns, compromised accounts, detector probing, false reports, poisoned reputation feeds, malicious public profiles, sandbox escapes, and insider misuse of content access. Product-specific threat models and adversarial fixtures are required before enabling private-content or automated-outbound enforcement in production.

Broad access creates broad abuse potential. Access controls, separation of duties, short retention, audit logs, detector provenance, product-specific scopes, and independently reviewable exceptions are part of the security boundary—not administrative follow-up.

## 11. Non-goals

This RFC does not:

- authorize generalized surveillance or censorship;
- define a legal basis for every deployment or jurisdiction;
- promise platform data, partnerships, or detectors that do not exist;
- authorize model-only enforcement;
- alter the published detector-output v1 contract in place;
- define a production zero-knowledge repetition protocol; or
- replace a product-specific response policy, security review, or data-retention schedule.

## 12. Operator review questions

The draft needs explicit operator decisions before acceptance:

1. Is Mode B's bounded access to chat, sent messages, downloads, and selected files correct, or should any of those require Mode C?
2. Which platform-safety exceptions may inspect otherwise private content, and what evidence threshold and review are required before each exception activates?
3. What default durations apply to consent, raw-content retention, structured findings, and enforcement evidence?
4. Must private-content detection be local/on-device by default, or may named products use a platform service when the receipt discloses it?
5. Which automated operations must declare the Automation / Operator tier, and what volume or behavior threshold makes the tier mandatory?
6. Should click-time sandboxing be mandatory for every supported product, or only for products that can isolate navigation without breaking expected workflows?
7. Should a future contract version replace raw `subject.value` with a privacy-safe reference for stored findings?

## 13. Acceptance and implementation gate

RFC-006 remains draft until the operator reviews §12 and marks the document Accepted. Acceptance authorizes implementation planning, not automatic deployment or content access. Each product profile, consent surface, sandbox, retention schedule, and private-content detector still requires its own tests, privacy/security review, native repository validation, and release decision.
