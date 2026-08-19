# 0001: Adopt the CairnVM identity and v1 namespace

- Status: accepted
- Date: 2026-08-17

## Context

The pre-release repository needs one canonical product and protocol namespace.
Names embedded in package metadata, commands, imports, paths, metrics, and reserved
format roles must agree before public release.

This is the sole accepted protocol decision. It accepts identifiers and role labels
only. All runtime and durable protocol decisions remain deferred to Phase 1 review
and executable tests, including encoding, capacity, parsing, algorithms, and
provider fit. The Phase 0 gate-evidence schema is administrative release evidence,
not a runtime or durable repository format.

## Decision

The product is CairnVM and the intended repository is
`baxter-barlow/cairnvm`.

<!-- cairnvm-contract:identity-surfaces -->
| surface | identifier |
|---|---|
| product | CairnVM |
| repository | baxter-barlow/cairnvm |
| runtime distribution | cairnvm-runtime |
| launcher distribution | cairnvm-launcher |
| runtime import | cairnvm |
| launcher import | cairnvm_launcher |
| command | cairnvm |
| environment prefix | CAIRNVM_ |
| local state | .cairnvm/ |
| Colab state | /content/cairnvm/ |
| Drive root | CairnVM/ |
| metrics prefix | cairnvm_ |
| discovery MAC domain | ASCII("CAIR-DISCOVERY-v1\0") |

The following four-byte magics and labels reserve namespace roles; they do not
approve a binary layout.

<!-- cairnvm-contract:magic-roles -->
| magic | role |
|---|---|
| CVIT | intent |
| CVMP | mapping |
| CVCH | commit-header |
| CVSE | primary-secret-envelope |
| CVRE | recovery-envelope |
| CVPK | pack |
| CVRC | remote-record |
| CVLR | local-record |
| CVKH | key-handoff-frame |

<!-- cairnvm-contract:discovery-property-range -->
| namespace | first | last |
|---|---|---|
| discovery-properties | cair_d00 | cair_d29 |

No released implementation, golden vector, or user repository predates this
decision. V1 will not read or emit predecessor namespaces.

## Consequences

- One exact identity spans documentation, package metadata, code, commands, paths,
  metrics, and reserved durable namespace roles.
- Phase 1 must validate current provider limits before choosing discovery encoding,
  property use, widths, counts, capacity, or parser bounds.
- Changing an accepted identifier requires a new ADR, compatibility analysis,
  executable tests, and independent review.

## Verification

Contract tests parse these tables structurally, compare them with the selected
state-model mirror, and compare package, command, and import identifiers with
canonical package metadata. A final one-time repository scan before publication
checks that the pre-release predecessor identity is absent from publishable source.
That migration check is not a permanent security boundary or a reason to maintain
special repository parsers.

Artifact verification continues to validate package inventories, reproducible
build paths, isolated installation, and smoke checks. Independent adversarial
approval remains required before publication.
