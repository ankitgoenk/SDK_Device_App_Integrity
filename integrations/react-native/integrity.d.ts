/**
 * React Native bridge surface for the device-integrity SDK.
 *
 * Design only — no implementation exists. See docs/adr/0006-integration-contract.md.
 *
 * The shape of these types is doing security work. The SDK collects evidence; the backend
 * decides. So there is deliberately no `isDeviceTrusted()` here, and the SDK's own opinion
 * is reachable only through `clientAdvisory`, where using it as a decision reads as wrong
 * at the call site rather than looking reasonable.
 */

export type Depth = 'QUICK' | 'STANDARD' | 'FULL';

/**
 * How much the detector believes its own observation.
 *
 * `INCONCLUSIVE` is not a weak positive. It means the check could not run, and it must
 * never be collapsed into "nothing found" — the distinction is enforced in the SDK and has
 * to survive the bridge.
 */
export type Confidence = 'INCONCLUSIVE' | 'POSSIBLE' | 'LIKELY' | 'CONFIRMED';

export type Category =
  | 'ROOT' | 'HOOKING' | 'APP_TAMPER' | 'ENVIRONMENT' | 'EMULATION' | 'ATTESTATION' | 'META';

/**
 * The SDK's own summary opinion, mirroring Kotlin `Verdict` exactly.
 *
 * **No member means "trusted", and that is the point (ADR-0009).** The bottom rung was called
 * `TRUSTED` until it was removed, because it made `if (verdict === 'TRUSTED') allow()` the
 * obvious thing to write — a decision taken on the device, from unsigned local evidence, which
 * is the single failure this architecture exists to prevent. `NO_EVIDENCE_OF_COMPROMISE` is the
 * replacement and it is an *absence*: a healthy device and a client patched to stay silent
 * produce it identically. Renaming was the whole defence, so do not reintroduce the old name and
 * do not treat the new one as its synonym.
 *
 * `tools/check-bridge-vocabulary.py` fails the build if this drifts from the Kotlin.
 */
export type Verdict =
  | 'NO_EVIDENCE_OF_COMPROMISE'
  | 'LOW_RISK'
  | 'SUSPICIOUS'
  | 'COMPROMISED'
  | 'UNKNOWN';

/**
 * What the backend's evidence service found, mirroring Kotlin `DeviceState` exactly.
 *
 * Three values, and there is no fourth. ADR-0008 removed attestation from that service's scope,
 * so it holds no authenticated anchor and has no route to a positive finding about a device.
 * `COMPROMISED` is the only thing it can assert; the other two are absences.
 */
export type DeviceState =
  | 'COMPROMISED'
  | 'NO_EVIDENCE_OF_COMPROMISE'
  | 'INSUFFICIENT_EVIDENCE';

export interface Signal {
  /** Stable identifier, e.g. `ROOT_DANGEROUS_PROPS`. Catalogued in docs/DETECTION_CATALOG.md. */
  readonly id: string;
  readonly category: Category;
  readonly confidence: Confidence;
  /** Bounded, non-PII. Never a path, an account, or a third-party package name in clear. */
  readonly evidence: Readonly<Record<string, string>>;
}

/**
 * The SDK's own scoring.
 *
 * Named to make misuse obvious. It is input to the backend's decision and useful telemetry
 * — a divergence between this and the server's own scoring is itself interesting — but a
 * compromised device can put anything here. Branch on `IntegrityDecision.decision`.
 */
export interface ClientAdvisory {
  readonly verdict: Verdict;
  readonly riskScore: number;
  readonly categoryScores: Readonly<Partial<Record<Category, number>>>;
}

export interface IntegrityReport {
  readonly sdkVersion: string;
  /** Idempotency key for the transport. Not a security token. */
  readonly reportId: string;
  readonly generatedAtMillis: number;
  readonly depth: Depth;
  /** Echo of the server challenge, when one was supplied. See ADR-0006 section 6. */
  readonly challenge: string | null;
  /**
   * Fraction of registered detectors that reached a conclusion, 0..1.
   *
   * Low coverage with no positive signals is *not* a clean device. The backend needs this
   * to tell "checked and found nothing" from "could not check".
   */
  readonly coverage: number;
  readonly signals: readonly Signal[];
  readonly clientAdvisory: ClientAdvisory;
}

export type IntegrityErrorCode =
  | 'NOT_INITIALIZED'
  | 'ALREADY_INITIALIZED'
  | 'EVALUATION_FAILED'
  | 'CANCELLED';

export interface IntegrityError extends Error {
  readonly code: IntegrityErrorCode;
}

export interface EvaluateOptions {
  readonly depth?: Depth;
  /** Bypass the freshness window and re-run. Defaults to false. */
  readonly force?: boolean;
  /** Server-issued nonce, echoed into the report. See ADR-0006 section 6. */
  readonly challenge?: string;
}

export interface Subscription {
  remove(): void;
}

/**
 * The backend's decision. This — and only this — is what the app enforces on.
 *
 * `UNAVAILABLE` (no decision was obtained) and `INSUFFICIENT_EVIDENCE` (a decision was
 * attempted and the evidence would not support one) are separate on purpose. Neither means
 * trusted.
 */
export interface IntegrityDecision {
  /**
   * The server's finding, plus one value the server never sends.
   *
   * `UNAVAILABLE` is synthesised by the app when no decision could be obtained at all — the
   * request failed, timed out, or was never made. It is deliberately distinct from
   * `INSUFFICIENT_EVIDENCE`, which is a decision the server did reach. Neither means trusted,
   * and neither does the third.
   */
  readonly decision: DeviceState | 'UNAVAILABLE';
  readonly decisionId: string;
  /**
   * The challenge this decision answers, or null.
   *
   * Unexpired is not the same as fresh. A sensitive action needs a decision bound to a
   * challenge minted for *that action*, not merely one that has not yet timed out — a finding
   * from app open says nothing about the device half an hour later.
   */
  readonly challenge: string | null;
  readonly evaluatedAtMillis: number;
  /** Server-authoritative. A client may shorten this, never extend it. */
  readonly expiresAtMillis: number;
}

/*
 * There is deliberately no `actions` field.
 *
 * It used to be here, as `actions?: readonly string[]`, and ADR-0008 had already removed it
 * from the service that would have populated it: "No action field. This service grades
 * evidence; it does not grant access, and an `ALLOW` it could emit would be an exoneration by
 * another name." An optional array of action strings is the shape `includes('ALLOW')` is
 * written against, which is exactly the read the ADR closes off.
 */

/**
 * Vocabulary for the app's own action table — deliberately two values and no operations.
 *
 * The app team owns which operations are sensitive, and that list lives in the app. The SDK
 * provides action-bound evaluation and never enumerates call sites. If a
 * `SENSITIVE_OPERATIONS` constant ever appears in this package, the architecture has leaked.
 */
export type ActionSensitivity = 'ORDINARY' | 'SENSITIVE';

/**
 * A decision that answers a challenge minted for a specific action.
 *
 * `challenge` is narrowed from `string | null`, so a decision from app open — which has no
 * action-specific challenge — is not assignable here. That is the point: the distinction
 * between "valid" and "fresh for this operation" is enforced by the compiler rather than
 * by a paragraph.
 */
export interface ActionBoundDecision extends IntegrityDecision {
  readonly challenge: string;
}

/**
 * Ordinary use: an unexpired decision is enough.
 *
 * `null` is a legitimate input and returns false — no decision is not a trusted decision
 * (hard rule 8).
 */
export function mayProceed(
  decision: IntegrityDecision | null,
  nowMillis: number,
): boolean;

/**
 * A sensitive action: the decision must answer the challenge minted for *this* operation, and
 * be unexpired, and not incriminate.
 *
 * Note what it cannot check: that the device is fine. There is no such value (ADR-0008), and
 * `NO_EVIDENCE_OF_COMPROMISE` is not a quiet spelling of one — a healthy device and a client
 * that suppressed every signal produce it identically (ADR-0007). So this predicate answers
 * "did our evidence service decline to accuse this device, in an answer minted for this
 * action, recently?" and nothing more. Passing it is a precondition for proceeding, never on
 * its own a reason to: the caller combines it with whatever authenticated signal they hold.
 *
 * The signature is the guard rail. Without it the natural thing to write is
 *
 *     if (decision.expiresAtMillis > Date.now()) allowTransaction();
 *
 * which turns the replay protection into a timestamp check and reintroduces exactly the
 * decision-replay this contract exists to close. Requiring the issued challenge as an
 * argument means the caller cannot express the sensitive case without having minted one.
 */
export function mayProceedWithSensitiveAction(
  decision: IntegrityDecision | null,
  issuedChallenge: string,
  nowMillis: number,
): decision is ActionBoundDecision;

export interface IntegrityModule {
  /** Registers detectors and returns. Starts no work and blocks nothing. */
  initialize(config?: { readonly expectedPackageName?: string }): Promise<void>;

  /**
   * Runs a sweep and resolves with the report.
   *
   * Never awaited on the startup path. Concurrent calls join the in-flight sweep rather
   * than starting a second one.
   */
  evaluate(options?: EvaluateOptions): Promise<IntegrityReport>;

  /**
   * Fires when a sweep completes, including one the app navigated away from.
   *
   * The promise from `evaluate` is convenient; this is what stops a `FULL` sweep's result
   * being lost because the user moved on.
   */
  addListener(event: 'integrityReport', listener: (report: IntegrityReport) => void): Subscription;
}
