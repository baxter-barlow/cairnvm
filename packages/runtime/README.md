# CairnVM Runtime

`cairnvm-runtime` is the experimental Phase 0 package for CairnVM. It currently
provides only the read-only, preliminary `cairnvm doctor` prerequisite probe. It
does not create disks, run virtual machines, access Google Drive, encrypt data,
checkpoint state, or recover repositories.

## Owner-authorized local smoke test

An external or merely received artifact has no independent trusted-launcher
verification path in Phase 0 and must not be executed. The repository owner or a
separately authorized collaborator may smoke-test an owner-built wheel only after
the exact clean-index candidate has passed `make verify-artifacts`. These are
operational instructions only and grant no permission.

The verifier already installs and probes the wheel in a disposable environment.
To repeat that smoke test for the same verified owner-built bytes:

```sh
python -m pip install ./cairnvm_runtime-0.1.0-py3-none-any.whl
cairnvm --version
cairnvm doctor --json
```

The [source repository](https://github.com/baxter-barlow/cairnvm),
[normative architecture](https://github.com/baxter-barlow/cairnvm/blob/main/Docs/Architecture-Spec.md),
and [security policy](https://github.com/baxter-barlow/cairnvm/security/policy)
govern development. This source-visible package is governed by the
[all-rights-reserved notice](https://github.com/baxter-barlow/cairnvm/blob/main/LICENSE);
no permission to copy, modify, or redistribute it is granted.
