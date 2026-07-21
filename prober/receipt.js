'use strict';

/**
 * ProofGuard fulfillment receipt emitter for independent unpaid probes.
 *
 * Schema reconciled against the live server implementation (VPS discovery
 * 2026-07-01):
 * - versions payment-expectation-receipt.v1 / payment-fulfillment-receipt.v1;
 * - receipt ids prefixed per_/pfr_;
 * - fulfillment links to expectation via expectation_receipt_hash;
 * - x402_payment_requirements_hash carries the hash of the 402 challenge.
 * For an unpaid probe the expectation receipt is built FROM the 402
 * challenge itself — the challenge is literally what the endpoint promised
 * before payment. verification_mode and claim_boundary must not be weakened:
 * this receipt only ever claims an unpaid 402-level probe. Paid probing is
 * Phase 2b and is intentionally not implemented.
 *
 * Signing: the server HMAC-signs its receipts with an in-process secret
 * (symmetric — not third-party verifiable). Prober receipts are
 * content-addressed (sha256 receipt_hash) and unsigned for now; Stage 2
 * plans Ed25519 signing with the dedicated attestor key so receipts are
 * publicly verifiable against the same identity that writes 8004 feedback.
 * No key material is handled in this module today.
 */

const crypto = require('node:crypto');

const CLAIM_BOUNDARY_UNPAID_PROBE =
  'Independent unpaid probe: ProofGuard requested the endpoint without payment and evaluated only the HTTP 402 x402 challenge. No payment was made and no paid response was observed; fulfillment beyond the 402 challenge is not attested.';

// ---------------------------------------------------------------------------
// action_ref — interop with the emerging agent-accountability correlation
// standard (argentum-core docs/spec/action-ref.md v1.1; adopted by the
// Microsoft AGT EvidenceAnchor SPI, SafeAgent, Nobulex, CrewAI et al).
//
// action_ref identifies the ACTION (who/what/scope/when), deliberately not
// the outcome — outcomes live in the signed receipt, which is exactly the
// division of labour that suits ProofGuard: every other record in that
// ecosystem is the operator's self-report of what happened; a ProofGuard
// receipt is a third-party OBSERVATION. Emitting the canonical envelope
// makes our observations correlatable with their self-reports.
//
// Conformance notes (all verified against the spec's byte-verified vectors):
// - preimage keys in lexicographic order: action_type, agent_id, scope,
//   timestamp; JCS RFC 8785 profile (ASCII values, no spaces, UTF-8);
// - timestamp MUST be RFC 3339 UTC with exactly 3-digit ms + 'Z'.
//   Date.prototype.toISOString() emits precisely this form, and probed_at
//   is produced by toISOString() in probe.js;
// - scope uses the spec's recommended <emitter>:<scope> namespacing.
// ---------------------------------------------------------------------------

const ACTION_REF_AGENT_ID = process.env.PROOFGUARD_AGENT_ID || 'proofguard.solsigs.com';
const ACTION_REF_TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/** Compute action_ref per action-ref.md v1.1. Returns null (never throws)
 *  if the timestamp is outside the profile domain — an unverifiable
 *  action_ref is worse than none. */
function computeActionRef(agentId, actionType, scope, timestamp) {
  if (!ACTION_REF_TS_RE.test(timestamp)) return null;
  // Keys listed in lexicographic order; JSON.stringify preserves insertion
  // order for these ASCII keys, matching JCS for this profile's domain.
  const canonical = JSON.stringify({
    action_type: actionType,
    agent_id: agentId,
    scope: scope,
    timestamp: timestamp,
  });
  return crypto.createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('hex');
}

/** Canonical receipt envelope v1.0 for a probe observation. */
function buildActionRefEnvelope(obs) {
  const scope = `proofguard:x402.probe:${obs.target_url}`;
  const ref = computeActionRef(ACTION_REF_AGENT_ID, 'x402.probe', scope, obs.probed_at);
  if (ref === null) return null;
  return {
    packet_version: '1.0',
    action_ref: ref,
    hash_algo: 'sha256',
    preimage_format: 'jcs-rfc8785-v1',
    preimage: {
      agent_id: ACTION_REF_AGENT_ID,
      action_type: 'x402.probe',
      scope: scope,
      timestamp: obs.probed_at,
    },
  };
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/** Deterministic JSON: sorted keys at every level, no whitespace. */
function canonicalJson(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}

/**
 * Probe score, 0-100. Used later as the 8004 giveFeedback value, so it must
 * be honest and reproducible from the observation alone.
 */
function scoreObservation(obs) {
  if (!obs.reachable) return 0;
  if (obs.status !== 402) return 5; // reachable but not an x402 endpoint as expected
  let score = 100;
  for (const code of obs.evidence_codes) {
    if (code.startsWith('FAIL_')) score -= 40;
    else if (code.startsWith('WARN_')) score -= 5;
  }
  if (obs.latency_ms > 5000) score -= 10;
  else if (obs.latency_ms > 3000) score -= 5;
  return Math.max(0, Math.min(100, score));
}

/**
 * Build a ProofGuard probe receipt from a probe.js observation.
 * @param {object} obs observation returned by probe()
 * @returns {object} receipt (stable, content-addressed)
 */
function buildReceipt(obs) {
  const score = scoreObservation(obs);
  const responseHash = sha256Hex(obs.response_body ?? '');
  // Hash of the raw 402 challenge — same role as the server's
  // x402_payment_requirements_hash field.
  //
  // HASH FIX: hash the bytes that actually carried the challenge, not the
  // response body. Header-canonical V2 sellers return "{}" as the body, so
  // sha256(body) is identical across every such seller — the digest would
  // collide and carry no evidentiary value. challenge_raw is set by probe.js
  // to the graded bytes (response body slice for body-canonical sellers,
  // the base64 PAYMENT-REQUIRED header for header-canonical ones).
  // Backward compatible: for body-canonical targets challenge_raw === the
  // previously hashed response_body slice, so existing digests are unchanged.
  const challengeRaw = obs.challenge_raw ?? obs.response_body ?? '';
  const challengeHash = obs.status === 402 ? sha256Hex(challengeRaw) : null;

  // Expectation receipt derived from the 402 challenge: what the endpoint
  // promised before payment. Only emitted when a challenge was observed.
  let expectationReceipt = null;
  if (obs.status === 402 && obs.accept_summary) {
    const a = obs.accept_summary;
    const decimals = Number.isInteger(a.decimals) ? a.decimals : 6;
    const atomic = /^\d+$/.test(String(a.maxAmountRequired)) ? a.maxAmountRequired : null;
    expectationReceipt = {
      version: 'payment-expectation-receipt.v1',
      endpoint_key: `${new URL(obs.target_url).origin}|${obs.method}|${new URL(obs.target_url).pathname}`,
      price: {
        amount: atomic === null ? null : (Number(atomic) / 10 ** decimals).toString(),
        amount_atomic: atomic,
        currency: a.currency || 'UNKNOWN',
        asset: a.asset,
        network: a.network,
      },
      promise: {
        scheme: a.scheme,
        pay_to: a.payTo,
        max_timeout_seconds: a.maxTimeoutSeconds,
      },
      x402_payment_requirements_hash: challengeHash,
      observed_at: obs.probed_at,
    };
    expectationReceipt.receipt_hash = sha256Hex(canonicalJson(expectationReceipt));
    expectationReceipt.receipt_id = `per_${expectationReceipt.receipt_hash.slice(0, 32)}`;
  }

  const fulfillment = {
    status: obs.status,
    ok: obs.challenge_valid === true,
    response_hash: responseHash,
    latency_ms: obs.latency_ms,
    evidence_codes: obs.evidence_codes,
  };

  const fulfillmentReceipt = {
    version: 'payment-fulfillment-receipt.v1',
    expectation_receipt_hash: expectationReceipt ? expectationReceipt.receipt_hash : null,
    x402_payment_requirements_hash: challengeHash,
    fulfillment,
  };
  fulfillmentReceipt.receipt_hash = sha256Hex(canonicalJson(fulfillmentReceipt));
  fulfillmentReceipt.receipt_id = `pfr_${fulfillmentReceipt.receipt_hash.slice(0, 32)}`;

  const receipt = {
    ok: obs.challenge_valid === true,
    product: 'SolSigs ProofGuard',
    verification_mode: 'proofguard_probed',
    claim_boundary: CLAIM_BOUNDARY_UNPAID_PROBE,
    probe: {
      version: 'proofguard-probe.v1',
      target_url: obs.target_url,
      method: obs.method,
      probed_at: obs.probed_at,
      reachable: obs.reachable,
      status: obs.status,
      latency_ms: obs.latency_ms,
      challenge_valid: obs.challenge_valid,
      spec_version: obs.spec_version ?? null,
      challenge_source: obs.challenge_source ?? null,
      accept_index: obs.accept_index ?? null,
      solana_leg: obs.solana_leg ?? false,
      checks: obs.checks,
      headers: obs.headers,
      accept_summary: obs.accept_summary,
      error: obs.error,
    },
    trust_score: {
      score,
      decision: score >= 80 ? 'ALLOW' : score >= 50 ? 'ALLOW_WITH_FLAGS' : 'DENY',
      reason_codes: obs.evidence_codes,
      endpoint_key: `${new URL(obs.target_url).origin}|${obs.method}|${new URL(obs.target_url).pathname}`,
    },
    expectation_receipt: expectationReceipt,
    fulfillment_receipt: fulfillmentReceipt,
    // Interop: canonical action_ref envelope (see block comment above).
    // Identifies this observation in the cross-system correlation standard;
    // outcome and evidence stay in the fields above, where they belong.
    action_ref_envelope: buildActionRefEnvelope(obs),
  };
  receipt.receipt_hash = sha256Hex(canonicalJson(receipt));
  return receipt;
}

module.exports = {
  buildReceipt,
  scoreObservation,
  canonicalJson,
  sha256Hex,
  CLAIM_BOUNDARY_UNPAID_PROBE,
  computeActionRef,
  buildActionRefEnvelope,
};
