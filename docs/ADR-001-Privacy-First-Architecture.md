# ADR-001 --- Privacy-First Architecture

**Status:** Accepted

## Context

Most fraud detection systems inspect private communications.

Although effective, this creates privacy, legal, and trust concerns.

FPL adopts privacy as a primary architectural constraint.

## Decision

Detection SHALL proceed using the following hierarchy:

1.  Metadata
2.  Behavioral patterns
3.  Graph relationships
4.  Public profile analysis
5.  Public links
6.  Conversation content (explicit user opt-in or narrowly defined
    platform safety exceptions)

## Rationale

This architecture:

-   Minimizes privacy intrusion.
-   Reduces regulatory exposure.
-   Improves user trust.
-   Lowers computational cost.
-   Produces explainable enforcement decisions.

## Consequences

### Advantages

-   Privacy-first by default.
-   Modular implementation.
-   Easier regulatory compliance.
-   High transparency.
-   Better user acceptance.

### Trade-offs

-   Some scams require content analysis for high confidence.
-   Metadata-only mode sacrifices some detection capability.
-   Enhanced Protection remains optional for users seeking stronger
    protection.

## Alternatives Considered

### Inspect all messages

Rejected due to privacy concerns.

### AI-first moderation

Rejected because opaque decision-making increases false positives.

### Manual moderation only

Rejected because it does not scale.

### Behavior-first layered detection

Accepted because it balances privacy, scalability, explainability, and
fraud prevention.

## Follow-on Work

Future ADRs should cover:

-   Risk scoring architecture
-   Detector plug-in model
-   User consent framework
-   Reputation graph
-   Browser extension architecture
-   Platform API integration
