# CairnVM Launcher

This package reserves the independent trust boundary that will verify and start
the CairnVM runtime on a fresh ephemeral host. It is intentionally non-executable in
Phase 0 and has no dependency on `cairnvm-runtime`.

Do not use it to download or run artifacts yet. Phase 0 requires an independently
reviewed release-verification and authorization boundary before downloaded
execution, but concrete verification and authorization mechanisms are deferred to
a Phase 1 ADR/spec gate. Implementation begins only after that gate accepts the
boundary and its executable success and failure-path criteria under the
[normative architecture](https://github.com/baxter-barlow/cairnvm/blob/main/Docs/Architecture-Spec.md).

The [CairnVM source repository](https://github.com/baxter-barlow/cairnvm) is the
canonical provenance for this package. This source-visible package is governed by the
[all-rights-reserved notice](https://github.com/baxter-barlow/cairnvm/blob/main/packages/launcher/LICENSE);
no permission to copy, modify, or redistribute it is granted.
