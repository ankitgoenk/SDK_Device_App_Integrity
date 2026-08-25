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

## Enforcement

`tools/check-no-network.sh` runs against the release AAR in CI. It fails if any shipped
class names a networking API — class files record every referenced type in their constant
pool, so `Socket` is visible whether or not the code is obfuscated — or if any shipped `.so`
imports a networking symbol.

**What it does not prove.** Reflection and `dlsym` both defeat it, which is why `dlsym`
itself is on the forbidden list rather than left as the obvious hole. The honest claim is
that it turns adding network IO from typing a line into deliberately hiding one, and makes
the deliberate version visible in review.

The check that would prove nothing, and is deliberately not used: asserting the SDK declares
no `INTERNET` permission. The host app holds that permission and the SDK inherits it, so a
library can open sockets without declaring anything.

Verified by rejection, not only by acceptance: a JVM class using `Socket` and an `.so`
calling `connect()` are both refused, and a clean library of each kind is accepted. The
first version of the native half matched nothing at all — symbols carry `@GLIBC_2.2.5`-style
version suffixes and the pattern was anchored, so it accepted a library that called
`connect()` outright. Android's bionic emits unversioned symbols, so CI would have passed
while the check did nothing.

## Consequences

- **Easier:** compliance story, security review, app-store review; smaller binary; no vendor
  backend to run.
- **Harder:** integrators must build the upload path and the backend verification; the
  end-to-end value only materialises once they do.
- **Mitigation:** ship `sample-backend` and a documented protocol
  ([SERVER_VERIFICATION.md](../SERVER_VERIFICATION.md)) so the missing piece is a copy-paste
  away rather than a design exercise.
