# 0005. Native failure model: status codes, validated reads, no exceptions

Date: 2026-08-25
Status: Accepted

## Context

Measured in CI (PR #4), arm64-v8a release, stripped:

| Configuration | Size |
| --- | --- |
| `c++_static`, throws `std::runtime_error` | 219,472 B |
| `c++_static`, `catch (...)` kept, nothing STL thrown | 217,944 B |
| `STL=none`, `-fno-exceptions` | **5,528 B** |

Removing `<stdexcept>` while keeping exceptions saves 0.7%. The cost is exception and
unwinding support itself. There is no gradient: 214 KB buys `catch (...)` and nothing else.

What that `catch (...)` protects against is close to nothing. Our own code throws nothing.
JNI functions do not throw C++ exceptions; they set *pending Java exceptions*, which
`catch (...)` never sees. Meanwhile the failure phase 3b actually risks — a SIGSEGV while
walking `/proc/self/maps` or reading a mapping that changed underneath us — is a signal.
`catch (...)` has never caught it and never will.

So the library was spending 97% of its budget on a runtime that does not cover its own
threat model, leaving ~37 KB of a 256 KB budget for detection.

## Decision

Build the native core with `ANDROID_STL=none` and `-fno-exceptions`. Replace the implicit
failure mechanism with an explicit one.

**1. Every native operation returns a status.** No implicit failure path exists.

```
kOk              the operation completed and its result is meaningful
kInvalidInput    a caller-supplied argument was rejected
kUnavailable     the thing being inspected could not be reached at all
kParseFailed     input was reached but could not be understood
kInternalError   a bug in our code; must never be produced by ordinary device state
```

Deliberately **not** in this list: anything resembling `INCONCLUSIVE`. That is a
`Confidence`, a judgement about evidence, and it belongs to the Kotlin scorer. The native
layer reports mechanically what happened; the Kotlin layer decides what it means. Letting
native return `INCONCLUSIVE` would move judgement into the layer least able to see the
policy — the same category error the project already refuses elsewhere.

**2. Nothing is dereferenced until it has been established as readable.** Before any read
derived from parsed input: overflow-check `address + length`, confirm the range lies inside
a mapping the process may read, and bound every buffer.

**3. Prefer failing reads over faulting reads.** Where a range must be read that we cannot
fully prove safe, read own memory through `pread` on `/proc/self/mem` rather than
dereferencing a pointer. An unmapped offset returns an error instead of a fault, which
converts a fatal condition into a status code. To be confirmed on-device in phase 3b before
being relied on.

**4. No dynamic allocation.** Fixed buffers, streamed reads with a hard cap. `STL=none`
removes libc++'s `operator new` anyway, and an allocator in a security library is one more
failure mode and one more thing to audit.

**5. Do not install a SIGSEGV handler and call it containment.** Catching the fault leaves
the process running with state of unknown validity, in a library whose entire purpose is
making trustworthy statements. A native fault is an implementation bug, not a detector
outcome. Fix the read that caused it; do not paper over it.

## Consequences

- **Easier:** ~250 KB of budget available for detection rather than ~37 KB; a smaller,
  auditable binary; failure paths that are visible in the signature of every function
  rather than implicit.
- **Harder:** C-like C++ with no `std::string` or containers; every error must be
  propagated by hand, and a forgotten status check is now a silent bug rather than an
  unwound stack. Reviewers must treat an ignored return value as a defect.
- **Unchanged:** the SIGSEGV risk. Exceptions never covered it. Points 2 and 3 are the
  actual mitigation, and they are new work, not a replacement for something being removed.
- **Test consequence:** `provokeFailure()` becomes meaningless — with no exceptions it can
  only return a constant, which tests nothing. It is replaced by feeding a malformed
  `/proc` fixture to the real parser and asserting a status code and a surviving process.
- **Enforced:** the `native-size-matrix` CI job already fails if the code stops building
  without exceptions, so this decision cannot be silently reversed.
