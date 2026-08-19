# CairnVM

CairnVM is a planned persistent virtual block device for running a QEMU guest on
ephemeral compute while storing authenticated, encrypted checkpoints in Google
Drive.

> **Current status:** experimental Phase 0 scaffold. The repository currently
> provides packaging, quality gates, and a read-only `cairnvm doctor` capability
> check. It does **not** yet create disks, start VMs, access Drive, encrypt data,
> upload checkpoints, or recover repositories.

The normative behavior and security contract are in
[`Docs/Architecture-Spec.md`](Docs/Architecture-Spec.md). The earlier
`Docs/Architecture-Draft.md` is retained only as historical context.

## Owner-authorized development setup

The commands in this section are operational documentation for the copyright
holder and collaborators covered by a separate written authorization. They do
not grant permission to download, copy, build, install, modify, or run CairnVM.

Authorized collaborators install [uv](https://docs.astral.sh/uv/), then run:

```sh
uv sync --locked --all-groups --all-packages
uv run --locked --all-packages cairnvm --version
uv run --locked --all-packages cairnvm doctor --json
make check
```

CairnVM does not install Git hooks automatically. The committed
`.pre-commit-config.yaml` is available only for explicit local and CI execution;
because Git hooks can be skipped or reconfigured, they are defense in depth, not
an enforcement boundary. The authoritative local gates are the explicit staged
checks below, backed by CI.

A fresh clone is already an index-clean snapshot, so setup can run `make check`
directly. For a change, run `make lint typecheck test`, stage only the intended
files, then run `make check` and `make scan-staged`. The artifact verifier
intentionally rebuilds from the Git index and rejects tracked drift and
nonignored untracked files. If either gate requires a correction, restage and
repeat both staged gates. CI repeats a full-history secret scan on pull requests
and pushes to `main`.

`doctor` is read-only and preliminary. It probes Python, QEMU, nbdkit and its
Python plugin, zstd, and optional `/dev/kvm` availability. Plugin presence and
device access do not certify runtime compatibility; the Phase 0 executable smoke
tests do that. A missing `/dev/kvm` is a warning because QEMU TCG is the planned
fallback; missing required tools return a nonzero exit code.

## Repository map

| Path | Purpose |
|---|---|
| `src/cairnvm/` | Installable runtime foundation and diagnostic CLI |
| `packages/launcher/` | Independent future bootstrap trust boundary |
| `tests/` | Offline unit and repository-contract tests |
| `Docs/Architecture-Spec.md` | Normative design authority |
| `Docs/architecture-state-model.toml` | Selected constants, limits, transitions, and recovery contracts the specification explicitly mirrors |
| `Docs/ADRs/` | Durable architectural decisions |
| `Docs/evidence/` | Reproducible phase-gate evidence |
| `OVERVIEW.md` | Component and trust-boundary summary |
| `ROADMAP.md` | Delivery phases and exit gates |

See `CONTRIBUTING.md` for the owner-authorized development policy, `SECURITY.md`
before handling credentials or guest images, and `PRIVACY.md` for the
pre-implementation Google user-data boundary.

CairnVM is source-visible proprietary software, not open source. Limited rights
arising directly under GitHub's Terms of Service apply while the repository is
publicly hosted there; otherwise the repository's
[proprietary source notice](LICENSE) reserves all rights. Build, installation,
and development instructions are for the owner and separately authorized
collaborators only.
