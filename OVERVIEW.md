# Project Overview

## Objective

CairnVM is intended to expose a virtual block device to QEMU on an ephemeral
runtime while keeping durable, client-authenticated checkpoints in Google Drive.
Correct recovery and honest durability reporting take priority over throughput.

`Docs/Architecture-Spec.md` is normative. This overview summarizes the current
boundary and planned ownership; `ROADMAP.md` alone owns mutable phase status.

## Current implementation

This is a Phase 0 scaffold; mutable phase status lives only in `ROADMAP.md`. The
launcher package boundary exists, but release verification, bootstrap
authorization, and downloaded execution do not. No data-path or
remote-persistence component is implemented.

<!-- cairnvm-contract:implementation-status -->
| component | status |
|---|---|
| CLI package and cairnvm entry point | implemented-scaffold |
| Read-only preliminary doctor diagnostics | implemented-scaffold |
| Independent launcher package boundary | implemented-scaffold |
| Quality, artifact, and secret-scanning gates | implemented-scaffold |
| Drive, cryptography, formats, and bootstrap | not-implemented-phase-1 |
| Internal block engine and offline checkpoints | not-implemented-phase-2 |
| Live checkpoints and internal backpressure | not-implemented-phase-3 |
| NBD, QEMU, supervision, and guest integration | not-implemented-phase-4 |
| Operational and privacy hardening | not-implemented-phase-5 |

## Planned ownership

<!-- cairnvm-contract:phase-ownership -->
| phase | owns |
|---|---|
| 0 | feasibility, scaffold boundaries, and honest evidence |
| 1 | formats, cryptography, Drive, bootstrap, and provider primitives |
| 2 | internal block requests, local durability, and offline checkpoint composition |
| 3 | live checkpoints and internal backpressure admission, refusal, and status |
| 4 | NBD wire and errors plus QEMU, supervisor, operator, and guest composition |
| 5 | operational and privacy hardening |

The independent launcher will own pre-execution verification and the bootstrap
authorization boundary. It must not import the runtime. The Drive client will be
the only runtime component with Drive authority. The internal block engine will
own guest block semantics and local durability. The checkpoint worker will own
remote publication and reconciliation. Phase 3 backpressure will remain an
internal admission, refusal, and status interface until Phase 4 maps it to NBD,
QEMU, supervisor, operator, and guest behavior.

Publication is not completed remote durability; completion requires both required
provider objects and the independently trusted anchor to reconcile as
present-as-intended for the authenticated checkpoint identity, parent, references,
and required head relationship.

## Non-negotiable properties

- Authenticate remote bytes before semantic use and enforce bounds before
  allocation.
- Refuse recovery and read-write selection when independently trusted freshness
  cannot be established; read-only diagnosis may label candidates unverified.
- Start every checkpoint attempt with fresh authenticated parent/head state and
  revalidation of the independently trusted freshness anchor, then reconcile fence
  acquisition bound to that pre-acquisition context before any other remote
  mutation. Bind every later mutation to the acquired authority through
  provider-object and anchor reconciliation and stop immediately if authority is
  lost or indeterminate or the anchor result is conflicting or indeterminate.
- A privileged Colab or compute host can observe or modify plaintext memory, keys,
  credentials, guest data, and local state and can subvert client authentication;
  protection from a malicious host is out of scope.
- Never upload plaintext guest blocks, plaintext secrets, or credentials. Never log
  plaintext guest data, credentials, tokens, passphrases, secret-envelope
  plaintext, keys, or derived keys.
- Keep destructive remote garbage collection out of v1.
- Execute no downloaded code before independent launcher verification succeeds.
