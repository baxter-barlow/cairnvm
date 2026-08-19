# Test Guide

These rules add to the repository `AGENTS.md` for `tests/`.

- Add a failing regression or contract test before implementation.
- Keep default tests offline, deterministic, parallel-safe, and independent of
  local credentials, Drive, `/dev/kvm`, QEMU, or nbdkit.
- Use synthetic keys, blocks, IDs, clocks, and fake services. Never use captured
  production payloads.
- Cover success, malformed input, bounds, retry idempotency, crash transitions,
  and fail-closed behavior for each protocol feature.
- Environment and fault-injection suites must use explicit pytest markers and write
  redacted evidence; a skipped prerequisite is not a passing gate.
