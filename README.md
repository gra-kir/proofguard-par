# ProofGuard — independent observation for x402 endpoints

**Every other record in the agent-accountability ecosystem is the operator's
claim about what happened. Ours is what we saw when we went and checked.**

ProofGuard is an independent prober and attestation layer for
[x402](https://github.com/x402-foundation/x402)-paid endpoints on Solana. It
requests an endpoint from the outside, without payment and without the
operator's cooperation, evaluates the HTTP 402 challenge against the x402
spec, and publishes the full observation as a content-addressed receipt.
Selected observations are attested on-chain to the
[8004 Agent Registry](https://github.com/QuantuLabs/8004-solana) on Solana
mainnet, where anyone can verify them — see **[VERIFY.md](./VERIFY.md)**.

## Why observation, not self-reporting

Post-settlement accountability systems are converging on a shared correlation
primitive ([action_ref](https://github.com/giskard09/argentum-core/blob/main/docs/spec/action-ref.md);
adopted by the Microsoft AGT EvidenceAnchor SPI, SafeAgent, Nobulex, CrewAI
and others). That standard is deliberately state-agnostic: it identifies
*actions*, never *outcomes*. Every record in it is an operator anchoring its
own account of what its agent did — tamper-evident self-reporting.

ProofGuard occupies the complementary position: a third party that goes and
looks. Receipts emit the canonical action_ref envelope (v1.0, byte-conformant
with the spec's published vectors), so ProofGuard observations correlate into
the same ecosystem — same key, different evidentiary class.

## What is attested — claim boundary

Unpaid 402-level probes. An attestation asserts that an endpoint's payment
challenge is **reachable, spec-conformant, and priced as declared** at probe
time. It does **not** assert that the endpoint delivers correct data after
payment. Every receipt carries this boundary verbatim in `claim_boundary`.
Paid fulfillment probing is future work and will be labelled as its own claim
when it exists — an attestation system that overstates its claims is worse
than none.

**Disclosure:** attestations of endpoints sharing an operator with ProofGuard
are tagged `probe-self-owned` on-chain. Independent targets are tagged
`probe-independent`. The relationship is on the permanent record, not in a
footnote.

## Repository contents

| Path | What it is |
|---|---|
| [`VERIFY.md`](./VERIFY.md) | Five-minute third-party verification of the on-chain trail — chain replay, seal recomputation, action_ref recompute. No ProofGuard system in the trust path. |
| [`spec/PAR-RECEIPTS.md`](./spec/PAR-RECEIPTS.md) | The Payment Attestation Receipt schema: expectation + fulfillment receipts, content addressing, scoring, action_ref envelope. |
| [`prober/`](./prober/) | Reference prober. `probe.js` (spec checks, v2 header-canonical challenge sourcing, Solana leg selection), `receipt.js` (receipt construction), `probe-readonly.js` (CLI, writes nothing). |

## Run the prober against any x402 endpoint

```bash
cd prober && npm install
node probe-readonly.js https://x402.agentutility.ai/defi-llama
node probe-readonly.js https://solsigs.com/dex
```

Output: PASS/FAIL, spec version, which `accepts[]` leg was graded (multi-chain
sellers are graded on their **Solana** leg), score, and evidence codes.
Read-only — no database, no receipt stored, nothing written.

Run the offline test suites (no network):

```bash
node test-fix.js          # challenge sourcing, leg selection, digest tests
node test-action-ref.js   # action_ref conformance incl. spec byte-vectors
```

## Live service

The probing and attestation pipeline runs continuously against a target set
that includes independent x402 sellers. On-demand attestation is available as
an x402-paid endpoint:

```text
POST https://solsigs.com/proofguard/attest   — 0.50 USDC, Solana mainnet
POST https://solsigs.com/proofguard/evaluate — 0.003 USDC
```

Receipts are published content-addressed at
`https://solsigs.com/proofguard/receipts/{sha256}` and served immutable —
the path is the receipt's own content hash, so the URL is the integrity check.

Example (live):
[`…39e76d21…f85583`](https://solsigs.com/proofguard/receipts/39e76d210d953299011958cad2e66014275abef68ea8ee1afd9403bd7df85583)

## Design principles

- **Independence.** The prober never runs inside the request path of any
  endpoint it grades, and grades endpoints without their cooperation.
- **Verifiability over trust.** Anything we claim on-chain, a stranger can
  check from public infrastructure alone. If our servers vanish, the
  evidence still verifies.
- **Honest failure.** Failed and degraded probes are recorded and attested
  with the same machinery as passes. A trail that can only say "95" is a
  rubber stamp.
- **Stated boundaries.** Each receipt says exactly what was and wasn't
  observed.

## License

MIT
