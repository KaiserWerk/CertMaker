# ADR-0001: Record decisions as ADRs

- Status: accepted
- Date: 2026-10-31
- Amended by: 

## Context

Architecture Decision Records (ADRs), introduced by Michael Nygard, are a standard: small, numbered, append-only markdown files that capture the
context and consequences of a single decision. They are widely adopted and tool-agnostic.

This is the first decision we make, so it must also bootstrap *the way we record decisions*. ADR-0001 records its own mechanism.

## Decision

We record every non-trivial decision about the CertMaker project as an ADR.

- ADRs live in the top-level `adr/` directory.
- Each ADR is one markdown file named `NNNN-kebab-case-title.md`, where `NNNN` is a zero-padded sequence number starting at `0001` (adr-tools / MADR naming convention).
- Each ADR follows Nygard's lightweight template: a title, a **Status**, a **Context**, the **Decision**, and its **Consequences**.
- `Status` is one of `proposed`, `accepted`, `superseded`, or `deprecated`. A superseded ADR is left in place and links to the ADR that replaces it; ADRs are append-only, never modified.

## Consequences

- From now on, choices about lifecycle mechanics, file shapes, and repository layout are captured here as numbered ADRs.
- ADRs may cover the **decision** stage of the lifecycle (idea -> proposal -> decision -> plan -> execution). Stages may be skipped if deemed unnecessary.