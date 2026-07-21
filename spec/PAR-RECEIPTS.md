# PAR — Payment Attestation Receipts

Schema reference for ProofGuard probe receipts, documented from the reference
implementation in [`../prober/receipt.js`](../prober/receipt.js). Everything
below is emitted by running code; nothing is aspirational.

## Design

A probe of one endpoint produces one **probe receipt** containing two nested,
individually content-addressed receipts:

- **`payment-expectation-receipt.v1`** — what the endpoint *promised* before
  payment, built from the 402 challenge itself: price (atomic units +
  decimal), asset, network, payTo, scheme, timeout. For an unpaid probe the
  challenge literally is the promise.
- **`payment-fulfillment-receipt.v1`** — what was *observed*: HTTP status,
  challenge validity, latency, evidence codes, and the hash of the raw
  challenge bytes. Links to the expectation via `expectation_receipt_hash`.

Both carry `x402_payment_requirements_hash`: sha256 of the exact bytes that
carried the challenge (`challenge_raw`). For body-canonical sellers that is
the response body; for v2 header-canonical sellers it is the base64
`PAYMENT-REQUIRED` header exactly as received. Hashing the *carrier bytes*
matters: header-canonical sellers all return `{}` as a body, so a body hash
would collide across every one of them and carry no evidentiary value.

## Content addressing

Every receipt object is canonicalized (sorted keys at every level, no
whitespace — see `canonicalJson`) and hashed sha256 into `receipt_hash`.
Receipt IDs are prefixed: `per_<hash32>` (expectation), `pfr_<hash32>`
(fulfillment). The outer receipt's `receipt_hash` covers everything,
including the nested receipts and the action_ref envelope — one changed byte
anywhere changes the outer hash. Published receipts are stored and served
under their own hash.

Independent probers observing the same endpoint state should converge on
identical evidence digests — cross-attestor digest matching is the intended
long-term verification primitive.

## Scoring

Deterministic and reproducible from the observation alone (`scoreObservation`):

```
unreachable                        → 0
reachable but not 402              → 5
otherwise start at 100:
  each FAIL_* evidence code        → −40
  each WARN_* evidence code        → −5
  latency > 5000 ms                → −10   (> 3000 ms → −5)
clamped to [0,100]
```

Decision: `≥ 80 ALLOW`, `≥ 50 ALLOW_WITH_FLAGS`, else `DENY`. The score is
also the value written on-chain when a receipt is attested — including
failures.

## Spec checks

`probe.js` applies version-aware x402 checks to the challenge: x402Version
present, accepts[] present, scheme/payTo/asset present, CAIP-2 network
enforcement for v2, atomic amount string, ResourceInfo (v2 top-level /
v1 accepts-level), https resource, timeout declared, and the normative v2
base64 `PAYMENT-REQUIRED` header. Multi-chain sellers are graded on the
first Solana `accepts[]` leg (`solana:` CAIP-2, then bare v1 forms), with
`WARN_NO_SOLANA_LEG` when a multi-leg seller has none. `challenge_source`
records whether the graded challenge came from the body or the header.

## Top-level receipt fields

| Field | Meaning |
|---|---|
| `ok` | challenge spec-valid |
| `verification_mode` | `proofguard_probed` — never elevated by caller input |
| `claim_boundary` | verbatim statement of what this receipt does and does not attest |
| `probe` | full observation: target, method, timing, status, per-check booleans, headers subset, accept summary, challenge_source, accept_index, solana_leg |
| `trust_score` | score, decision, reason codes, endpoint key |
| `expectation_receipt` / `fulfillment_receipt` | as above |
| `action_ref_envelope` | canonical envelope v1.0 (below) |
| `receipt_hash` | sha256 of canonical form of everything above |

## action_ref envelope

Receipts embed the canonical receipt envelope v1.0 of the
[action-ref v1.1 spec](https://github.com/giskard09/argentum-core/blob/main/docs/spec/action-ref.md):

```json
{
  "packet_version": "1.0",
  "action_ref": "<sha256 hex>",
  "hash_algo": "sha256",
  "preimage_format": "jcs-rfc8785-v1",
  "preimage": {
    "agent_id": "proofguard.solsigs.com",
    "action_type": "x402.probe",
    "scope": "proofguard:x402.probe:<target_url>",
    "timestamp": "<probed_at, RFC 3339 UTC, 3-digit ms, Z>"
  }
}
```

Conformance: the implementation reproduces both byte-verified vectors
published in the spec (`fdd7f810…`, `36fe8d05…` — see
[`../prober/test-action-ref.js`](../prober/test-action-ref.js)). Timestamps
outside the spec's profile domain cause the envelope to be omitted rather
than emitted unverifiably.

`action_ref` identifies the observation event; evidence lives in the receipt
body. This mirrors the spec's own state/identity separation.

## On-chain attestation

Selected receipts are attested to the 8004 Agent Registry
(`give_feedback`): `value`/`score` = probe score, `tag1` = `x402`,
`tag2` = `probe-self-owned` | `probe-independent` (common-ownership
disclosure), `endpoint` = target URL, `feedbackUri` = the receipt's public
content-addressed URL, `feedbackFileHash` = sha256 of the exact receipt file.
The registry's SEAL v1 computes a seal over all of these on-chain, which is
what makes third-party verification possible — see
[VERIFY.md](../VERIFY.md).

External (non-common-ownership) endpoints are attested on-chain only under a
consent-and-binding policy; otherwise their observations remain off-chain
signed receipts. Off-chain receipts are correctable; marks on someone else's
permanent record are not.
