# 0012. Diagnostics describe what ran, and never enter the report

## Status

Accepted, 2026-09-02.

## Context

The SDK reports what it observed. Until now that was all it reported, and a reasonable question
kept coming back from anyone shown a run: *which checks actually executed?* On a rooted phone the
screen showed two findings and nothing else, and there was no way to tell twenty checks that
found nothing from two checks and eighteen that never ran.

That is a real gap for the people who most need to answer it — a QA build, a bug report, a tester
running the app on hardware the team does not own. Device coverage is this project's binding
constraint: every verdict in `docs/DETECTION_TRIAGE.md` rests on a handful of phones, and twice
in two days a false positive was found only because a third device existed. Making the SDK
describe its own run is the cheapest way to widen that.

The obvious implementation is to put the list in `IntegrityReport`. That is the one thing it
must not do.

## Decision

**Diagnostics are delivered in-process to the host through `DiagnosticsSink`, and are never part
of `IntegrityReport`, `ReportWire`, or anything the backend accepts.**

`IntegrityDiagnostics` carries one `DetectorRun` per registered detector: its id, category,
`minDepth`, a `RunOutcome`, how many signals it emitted, and how long it took.

## Consequences

**A list of checks that found nothing is a trust claim, and hard rule 9 forbids trust claims in a
report.** "Seventeen checks ran, sixteen found nothing" reads as a clean bill of health, and it is
*cheaper to forge than the evidence it stands in for*: a stripped SDK emitting that list earns the
same finding as a healthy device, at no cost to the attacker. ADR-0007 already refused a
client-supplied `coverage` for this reason. The execution-coverage fraction that does travel is
the most that can be, and `docs/TESTING.md` §9 records why even that must not be read as threat
coverage.

**`RunOutcome.FOUND_NOTHING` is the most common outcome and the least informative.** A detector
that looked and saw nothing, and a detector defeated by a cloak, produce the same value — that is
ADR-0007's asymmetry showing through the vocabulary rather than a shortcoming of it. Every surface
that renders this must say so next to the number, not in documentation: the sample app's screen
does, and its share text puts the sentence above the first result. A test pins that ordering,
because the disclaimer is the kind of thing a later edit trims for brevity.

**`SKIPPED_FOR_DEPTH` is not `FOUND_NOTHING`.** A `FULL`-only detector that never ran at `QUICK`
must not read as having checked and found nothing. Keeping them distinct is most of the value of
the vocabulary.

**This is not telemetry.** Nothing here is signed, and nothing is accepted server-side. A host
wiring `DiagnosticsSink` to an analytics pipeline in the hope of a trust signal will find none;
that is stated on the interface itself.

## Alternatives considered

**Put it in the report behind a debug flag.** Rejected: the flag is set by the client, and a
client under attacker control sets it however it likes. A field that exists on the wire is a field
that can arrive on the wire.

**Log it instead.** Insufficient. The people who need it most are testers on devices the team does
not own, who need something they can read and send back — not a logcat buffer.
