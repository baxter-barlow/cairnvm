# Privacy Notice (Pre-Implementation)

CairnVM is currently a local feasibility scaffold. It does not request Google
OAuth authorization, access Google user data, upload VM data, operate a hosted
service, or collect telemetry.

This repository notice is not the production OAuth privacy policy. Before any
external production OAuth client is enabled, CairnVM must publish a public
homepage and privacy policy on the same owner-verified domain and link them from
the Google OAuth consent screen. That policy must accurately disclose how the
released software accesses, uses, stores, and shares Google user data, including:

- the exact Drive scopes and data categories used;
- local token, cache, checkpoint, log, and telemetry handling;
- any service provider or third-party sharing;
- retention, deletion, export, revocation, and support procedures.

The implementation may use Google user data only as that future policy discloses.
Until this roadmap gate is complete, production OAuth distribution is blocked.
