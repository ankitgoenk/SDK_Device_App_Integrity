# Architecture Decision Records

Short, immutable records of decisions with lasting consequences. One file per decision,
numbered sequentially, never edited after acceptance — superseded instead.

Template:

```markdown
# NNNN. Title

Date: YYYY-MM-DD
Status: Proposed | Accepted | Superseded by ADR-XXXX

## Context
What forces are at play?

## Decision
What we are doing.

## Consequences
What becomes easier, what becomes harder, what we accept.
```

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-evidence-based-api.md) | Evidence-based API instead of boolean checks | Accepted |
| [0002](0002-native-core.md) | A native (C++) core for hooking and code-integrity checks | Accepted |
| [0003](0003-no-network-in-sdk.md) | The SDK performs no network IO | Accepted |
| [0004](0004-package-visibility.md) | Curated `<queries>` instead of `QUERY_ALL_PACKAGES` | Accepted |
| [0005](0005-native-failure-model.md) | Native failure model: status codes, validated reads, no exceptions | Accepted |
| [0006](0006-integration-contract.md) | The app/SDK/backend integration contract | Accepted; partly superseded by 0008 |
| [0007](0007-asymmetric-trust.md) | Evidence can incriminate, never exonerate | Accepted; partly superseded by 0008 |
| [0008](0008-attestation-out-of-scope.md) | Attestation leaves our scope; the backend becomes an evidence service | Accepted |
