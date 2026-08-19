# Architecture Decision Records

Create `NNNN-short-title.md` for a decision that changes component ownership,
trust boundaries, dependencies, durable formats, recovery semantics, or phase
gates. Use this template:

```markdown
# NNNN: Decision title

- Status: proposed | accepted | superseded
- Date: YYYY-MM-DD
- Spec sections: links

## Context

Facts, constraints, and the decision pressure.

## Decision

The exact choice and its enforceable boundaries.

## Consequences

Benefits, costs, migration impact, and new tests.

## Verification

Commands, evidence path, and independent review result.
```

An ADR explains why; `Docs/Architecture-Spec.md` remains the normative protocol.

## Accepted decisions

- [`0001-cairnvm-identity.md`](0001-cairnvm-identity.md) — CairnVM identity and
  v1 protocol namespace.
