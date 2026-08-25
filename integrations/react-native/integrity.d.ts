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
  readonly verdict: 'TRUSTED' | 'SUSPICIOUS' | 'COMPROMISED' | 'UNKNOWN';
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
  readonly decision: 'TRUSTED' | 'COMPROMISED' | 'UNAVAILABLE' | 'INSUFFICIENT_EVIDENCE';
  readonly decisionId: string;
  /**
   * The challenge this decision answers, or null.
   *
   * Unexpired is not the same as fresh. A sensitive action needs a decision bound to a
   * challenge minted for *that action*, not merely one that has not yet timed out — a
   * TRUSTED from app open says nothing about the device half an hour later.
   */
  readonly challenge: string | null;
  readonly evaluatedAtMillis: number;
  /** Server-authoritative. A client may shorten this, never extend it. */
  readonly expiresAtMillis: number;
  readonly actions?: readonly string[];
}

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
 * A sensitive action: the decision must answer the challenge minted for *this* operation,
 * and be unexpired, and be TRUSTED.
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
