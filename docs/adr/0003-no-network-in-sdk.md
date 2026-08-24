# 0003. The SDK performs no network IO

Date: 2026-08-24
Status: Accepted

## Context

An integrity SDK that uploads reports itself would be simpler for integrators. It would also:

- put the SDK inside the host's privacy and consent boundary, forcing us to own GDPR/DPDP
  obligations, data safety declarations and retention;
- duplicate (and likely weaken) the host's TLS pinning and network configuration;
- give attackers a network endpoint to fingerprint and block;
- make the SDK look like a tracker to reviewers and researchers.

## Decision

The SDK exposes a `ReportSink` interface and ships no HTTP client, no endpoint, no `INTERNET`
permission requirement. The host transports reports over its own authenticated, pinned
channel and owns storage and retention.

## Consequences

- **Easier:** compliance story, security review, app-store review; smaller binary; no vendor
  backend to run.
- **Harder:** integrators must build the upload path and the backend verification; the
  end-to-end value only materialises once they do.
- **Mitigation:** ship `sample-backend` and a documented protocol
  ([SERVER_VERIFICATION.md](../SERVER_VERIFICATION.md)) so the missing piece is a copy-paste
  away rather than a design exercise.
