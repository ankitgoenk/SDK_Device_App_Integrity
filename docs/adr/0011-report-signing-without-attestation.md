# 0011. Report signing without attestation

Date: 2026-08-31
Status: Accepted. Supersedes the "Signing" section of
[`docs/SERVER_VERIFICATION.md`](../SERVER_VERIFICATION.md), which was written before
[ADR-0008](0008-attestation-out-of-scope.md) and specifies a scheme this project can no longer
build. Applies [ADR-0007](0007-asymmetric-trust.md)'s asymmetry to the transport layer.

## Context

Two items were left in phase 7: report signing, and parsing the canonical wire form
server-side. The first is not one feature among several — hard rule 6 makes it a gate on
*every* weight promotion in the project. No signal may carry a non-zero weight until reports
are signed and verified, so nothing detected anywhere can affect a score until this exists.

`docs/SERVER_VERIFICATION.md` describes how to build it:

> **Preferred:** ECDSA P-256 with a key generated in the **Android Keystore**, hardware-backed
> where available, with **key attestation** so the backend can verify the key really lives in
> a TEE/StrongBox.
>
> **Fallback (no Keystore attestation):** HMAC-SHA256 with a key derived in native code from
> the build baseline.

That was written two ADRs ago and neither half survives contact with what the project has
since decided.

**The preferred scheme is attestation.** Verifying a Keystore attestation certificate chain
is a backend check that concludes something favourable about a device's hardware. ADR-0008
says this project performs no device attestation and its backend has no route to a trusted
state; hard rule 9 says nothing in a report may raise trust. A TEE-backed key would be
exactly such an input — and the most persuasive kind, which is what makes it worth naming
rather than quietly not building.

**Remove the attestation and the scheme stops proving anything.** The public key then arrives
self-reported. Anyone can generate a P-256 keypair, sign a report of their choosing with it,
and present both. The signature verifies perfectly and establishes only that whoever
assembled the report held a key they had just chosen — which is what the TLS session already
established. The attestation was not a hardening step on top of the ECDSA design; it was the
entire source of the design's meaning.

**The documented fallback is a global secret.** A key derived in native code from the build
baseline is identical in every install. Extracted once, from any copy of the APK, by anyone,
it forges reports for every user of the app permanently, and no property of a forged report
distinguishes it from a real one. That is not a weaker version of the preferred scheme; it
fails differently and worse, because its compromise is silent and total rather than per-device.

So the honest position is that phase 7's remaining gate had no implementable design, and the
document describing it read as though it did.

## Decision

### 1. ECDSA P-256 in the Android Keystore, enrolled over the host's authenticated channel

The keypair is generated in the Android Keystore, non-exportable, hardware-backed where the
device offers it. The public key is registered with the backend **through the integrator's own
authenticated session** — the same session that already carries `sessionId` into
`ReportSubmission`.

The binding to an identity therefore comes from the integrator's authentication, which they
already run, and not from an attestation this project would have to perform. That keeps
ADR-0008 intact while giving the signature something to mean. It also matches ADR-0006's
division of labour exactly: the app owns transport and auth, we own evidence.

What this buys, stated narrowly so it is not oversold:

- Forging a report for a session now requires the private key enrolled for that session.
- The key is non-exportable and per-device, so compromise is per-device. There is no
  equivalent of extracting one secret and forging for the whole install base.
- Enrollment is an authenticated event, so a key that was never enrolled cannot be used, and
  a key can be revoked without shipping a new build.

What it does not buy, which is most of what people expect from signing:

- **It does not defeat a rooted device.** A Keystore key is used, not read; an attacker with
  root asks the Keystore to sign whatever they like and gets a perfect signature over a
  fabricated report. This was already true of the attested design and is the reason ADR-0006
  §"Trust boundary" said the client-side battle is lost on a rooted device.
- **It does not make a clean report meaningful.** ADR-0007's hole is untouched: suppress every
  signal, sign the empty report correctly, and the backend still sees no evidence of
  compromise. Signing addresses forgery, not silence.

### 2. Signature verification may incriminate. It may never exonerate

This is the load-bearing rule, and it inverts what a reader expects verification to do.

**Signals in a report are scored whether or not the signature is good.** A bad signature does
not discard the evidence that arrived with it.

The reason is ADR-0007's asymmetry applied one layer down. A hostile client has no motive to
invent evidence against itself, so an incriminating signal is credible on its content alone
and needs no proof of origin. Grant a bad signature the power to suppress evidence and you
have built the escape hatch: a genuinely compromised device strips or corrupts its signature
and converts `COMPROMISED` into `INSUFFICIENT_EVIDENCE`. Verification would then be doing the
one thing ADR-0007 exists to prevent — letting something in the report move a decision toward
trust — with the added irony that *breaking* the security mechanism is what triggers it.

The converse holds and matters just as much: **a valid signature adds nothing.**
`NO_EVIDENCE_OF_COMPROMISE` remains the ceiling with a perfect signature exactly as without
one. There is no state, field or code path where a good signature improves an outcome. A test
pins this by verifying that a signed and an unsigned submission carrying the same signals
produce byte-identical findings.

So a signature check has exactly one direction available to it, and it is used:
a report that *claims* a key and fails to prove it emits `SRV_REPORT_SIGNATURE_INVALID`,
which enters `RiskScorer` as evidence like any other and can only move the finding toward
`COMPROMISED`.

The distinction between unsigned and badly-signed is deliberate. An unsigned report from a
host that never enrolled a key is an unfinished integration, not an attack, and accusing it
would make the signal useless in exactly the deployments that have not adopted signing yet.
A report that presents a `keyId` and a signature that does not verify is a different claim:
something asserted an origin it could not substantiate.

### 3. Verify over the bytes received, then parse them

The backend verifies the signature over the exact bytes it was given, and only then parses
those bytes into a report.

The tempting order — parse the submission, re-serialise it with `ReportWire`, verify the
signature over the result — is wrong in a way that is invisible while the two implementations
agree. It makes every canonicalisation difference a signature bypass: anything a parser
accepts but a serialiser renders differently becomes a payload whose verified bytes are not
its interpreted bytes. Verifying first removes the entire class rather than defending against
its members one at a time, and it is why report parsing and report signing landed together
instead of in the order the plan listed them.

### 4. Envelope format

A compact, JWS-shaped form, because base64url contains no `.` and so the framing is
unambiguous without a length convention anyone has to remember:

```
IGS1.<b64url(header)>.<b64url(canonicalReport)>.<b64url(signature)>
```

The signature covers the ASCII bytes of everything before the final separator —
`IGS1.<b64url(header)>.<b64url(canonicalReport)>` — so the header is signed along with the
payload and cannot be swapped. `header` is canonical JSON carrying `keyId`, `packageName` and
`sdkVersion`.

The nonce needs no place here: `challenge` is already inside the canonical report, put there
by ADR-0006 §6 precisely so it could not be attached after the fact. Re-stating it in the
envelope would create a second copy that could disagree with the first.

Base64url is hand-rolled in `integrity-model` rather than delegated to `java.util.Base64`,
which is API 26 and would raise `minSdk` from 24 for a codec. `ReportWire` hand-rolls its JSON
and its hex for a related reason, documented there.

## Consequences

**The gate on weight promotion is now half-open, not open.** Hard rule 6 requires signing
"shipped and verified". This ships it. The second gate — reports joinable to authoritative
fraud outcomes — is untouched and remains the harder one, since the join key must come from
the host without a device identifier entering the report (hard rule 3).

**`SRV_REPORT_SIGNATURE_INVALID` is the second server-side `SignalId`,** joining
`ATT_APP_NOT_RECOGNISED`. Unlike that one, this project does emit it: it is produced by
`sample-backend` during verification, not by any detector on the device. The catalog marks it
`SRV` and it ships at `INFORMATIONAL` like everything else.

**A new false-positive surface, on the accusing side.** Key rotation, a restored backup, a
cleared Keystore after a lock-screen change, and a device that lost its keys to a factory
reset all produce a signature that does not verify against the enrolled key. Every one of them
is an ordinary user, and every finding this service makes is an accusation (ADR-0008). The
signal is therefore raised for *failing* verification, never for a key the backend simply does
not recognise — an unknown `keyId` is a re-enrollment, which the host's authenticated channel
handles without our help.

**Reversing to HMAC is possible and additive.** `keyId` was designed to distinguish key
classes, and nothing here consumes it beyond lookup. If an offline or pre-enrollment path is
ever needed, it arrives as another key class, scored no higher than this one, and this
decision does not have to be undone first.
