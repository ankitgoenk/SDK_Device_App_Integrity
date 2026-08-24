package io.integrity.attestation.play

import io.integrity.core.Detector

/**
 * ATT_* signals from the Play Integrity API.
 *
 * Phase 0 scaffold. Phase 7 implements Standard requests on the hot path and Classic
 * requests for high-value actions, binding the token to a server nonce via requestHash.
 *
 * The token is never verified on-device: the client cannot be trusted to grade itself.
 * Verification, verdict mapping and re-scoring happen on the backend — see
 * docs/SERVER_VERIFICATION.md.
 */
public object PlayAttestation {

    public fun all(): List<Detector> = emptyList()
}
