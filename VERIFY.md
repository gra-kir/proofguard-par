# Verifying the ProofGuard attestation trail

**You do not have to trust us. This document shows you how to check.**

ProofGuard publishes on-chain attestations of x402 endpoint probes to the
[8004 Agent Registry](https://github.com/QuantuLabs/8004-solana) on Solana
mainnet. Every attestation is independently verifiable using only public
infrastructure: the Solana chain, the public 8004 indexer, and the published
receipt files. No ProofGuard system is in the trust path — if our servers
vanished tomorrow, every check below would still run.

Time required: about five minutes.

## What is being claimed

Each attestation asserts: *ProofGuard probed endpoint E at time T without
payment, evaluated its HTTP 402 x402 challenge against spec, scored it S, and
published the full evidence as receipt file R.* The on-chain record binds all
of that together cryptographically.

**Claim boundary — read this before anything else.** These are unpaid
402-level probes. They attest that an endpoint's payment challenge is
reachable, spec-conformant, and priced as declared. They do NOT attest that
the endpoint delivers correct data after payment. Every receipt carries this
boundary in its `claim_boundary` field. An attestation system that overstates
its claims is worse than none.

**Disclosure.** Attestations of SolSigs' own endpoints are tagged
`probe-self-owned` on-chain — ProofGuard and SolSigs share an operator, and a
self-assessment labelled as independent would be a lie. Independent targets
are tagged `probe-independent`. Attestations written before 2026-07-21 carry
the older undifferentiated tag `probe`; at that time the trail was 100%
self-owned targets, so no ambiguity is introduced.

## Public coordinates

| Thing | Value |
|---|---|
| Agent asset (subject) | `HddvtSB96GcmKuBnL1TMDp2GRTavvzpSt2wa8wky2jXo` |
| Attestor wallet (author) | `GDfyDptVYTHfumAN8DkaHx42qcer6JJphkjCkypuBDLS` |
| 8004 registry program (mainnet) | `8oo4dC4JvBLwy5tGgiH3WwK4B9PWxL9Z4XjA2jzkQMbQ` |
| Public indexer | `https://8004-indexer-main.qnt.sh` (SDK default) |
| Receipt files | `https://solsigs.com/proofguard/receipts/{sha256}` |

A live one you can open right now — the receipt attested at feedback index 72:
[`…39e76d210d953299011958cad2e66014275abef68ea8ee1afd9403bd7df85583`](https://solsigs.com/proofguard/receipts/39e76d210d953299011958cad2e66014275abef68ea8ee1afd9403bd7df85583)

(The path must be exactly 64 hex characters — that is the receipt's own content
hash. Anything else is not routed to the receipt store.)

## Setup

```bash
mkdir pg-verify && cd pg-verify && npm init -y --silent
npm install --silent 8004-solana @solana/web3.js
```

## Check 1 — the indexer is not lying (chain replay)

The 8004 registry stores feedback as events plus a rolling keccak256
hash-chain digest in the on-chain `AgentAccount`. Replaying every indexed
event through the chain and comparing the final digest against on-chain state
proves the indexer has not altered, omitted, or invented anything: one changed
byte anywhere and the digests diverge.

```js
// check1.js — node check1.js
import { SolanaSDK } from '8004-solana';
import { PublicKey } from '@solana/web3.js';

const sdk = new SolanaSDK({ cluster: 'mainnet-beta' }); // read-only, no keys
const asset = new PublicKey('HddvtSB96GcmKuBnL1TMDp2GRTavvzpSt2wa8wky2jXo');

const r = await sdk.verifyIntegrityFull(asset);
console.log('valid:', r.valid);
console.log('on-chain digest :', r.chains.feedback.onChain);
console.log('replayed digest :', r.chains.feedback.indexer);
console.log('counts on-chain/indexer:', r.chains.feedback.countOnChain, '/', r.chains.feedback.countIndexer);
```

Expected: `valid: true`, both digests identical, counts equal. You have now
established — against the chain, not against us or QuantuLabs — that the
indexer's event set for this agent is exactly what happened on-chain.

Use any RPC you like via `rpcUrl:` — the point is that it's *your* choice of
node, not ours.

## Check 2 — each attestation is bound to its exact receipt file

The registry's SEAL v1 scheme has the **program** compute a `seal_hash`
on-chain from all feedback parameters — including the sha256 of the receipt
file — and emit it in the event. So: fetch the receipt file from its public
URL, hash it, recompute the seal, compare with the indexed seal. A match
proves the on-chain record committed to *that exact file*, byte for byte, at
write time. The file cannot have been swapped or edited afterwards.

```js
// check2.js — node check2.js [feedbackIndex]
import { SolanaSDK, computeSealHash } from '8004-solana';
import { PublicKey } from '@solana/web3.js';
import crypto from 'node:crypto';

const sdk = new SolanaSDK({ cluster: 'mainnet-beta' });
const asset = new PublicKey('HddvtSB96GcmKuBnL1TMDp2GRTavvzpSt2wa8wky2jXo');
const idx = process.argv[2] ?? '0';

const events = await sdk.getFeedbacksFromIndexer(asset);
const ev = events.find((e) => String(e.feedbackIndex) === String(idx));
if (!ev) throw new Error(`no event at index ${idx} (have ${events.length})`);

console.log('endpoint :', ev.endpoint);
console.log('score    :', ev.score, ' tags:', ev.tag1, '/', ev.tag2);
console.log('receipt  :', ev.feedbackUri);

// Fetch the published receipt file and hash it yourself.
const res = await fetch(ev.feedbackUri);
if (!res.ok) throw new Error(`receipt fetch failed: ${res.status}`);
const fileBytes = Buffer.from(await res.arrayBuffer());
const fileHash = crypto.createHash('sha256').update(fileBytes).digest();
console.log('sha256(receipt file):', fileHash.toString('hex'));

// Recompute the seal from INDEXED params + YOUR OWN hash of the file.
const computed = computeSealHash({
  value: BigInt(ev.value),
  valueDecimals: Number(ev.valueDecimals ?? 0),
  score: ev.score === null || ev.score === undefined ? null : Number(ev.score),
  feedbackFileHash: fileHash,
  tag1: ev.tag1, tag2: ev.tag2,
  endpoint: ev.endpoint, feedbackUri: ev.feedbackUri,
});
const match = computed.toString('hex') === Buffer.from(ev.sealHash).toString('hex');
console.log('seal recomputed == seal on-chain:', match);
if (!match) throw new Error('SEAL MISMATCH — the published file is not the attested file');
```

Run it for any index (0 through the current count). Every input to the seal
came from the indexed event — which Check 1 just proved faithful to the chain
— except the file hash, which you computed yourself from the public file. A
match therefore proves the binding with no ProofGuard system involved.

The receipt file itself contains the full probe observation: every spec check
run, the challenge as received, latency, evidence codes, the score
derivation, and the claim boundary. Read it. The receipt is served with
`Cache-Control: immutable` and named by its own content hash.

## Check 3 — cross-system correlation (action_ref)

Receipts issued from 2026-07-21 carry a canonical `action_ref` envelope per
the [action-ref v1.1 spec](https://github.com/giskard09/argentum-core/blob/main/docs/spec/action-ref.md)
(the derivation shared by the Microsoft AGT EvidenceAnchor SPI, SafeAgent,
Nobulex, CrewAI and others). Recompute it from the four preimage fields:

```js
// check3.js — after fetching a receipt as in check2:
const receipt = JSON.parse(fileBytes.toString('utf8'));
const env = receipt.action_ref_envelope;
if (env) {
  const p = env.preimage;
  const canonical = JSON.stringify({
    action_type: p.action_type, agent_id: p.agent_id, scope: p.scope, timestamp: p.timestamp,
  });
  const ref = crypto.createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('hex');
  console.log('action_ref recomputes:', ref === env.action_ref);
}
```

One distinction worth understanding when correlating: records in the
action_ref ecosystem are generally *self-reports* — an operator anchoring its
own account of what its agent did. A ProofGuard record is an *observation* —
a third party probed the endpoint and published what it saw. Same correlation
key, different evidentiary class.

## What each check does and does not establish

| Check | Proves | Does not prove |
|---|---|---|
| 1 | Indexer event set == on-chain history | Anything about individual receipts |
| 2 | On-chain record is bound to the exact published receipt file | That the probe's *judgment* was correct |
| 3 | Receipt is correlatable across accountability systems | Anything evidentiary on its own |

"The probe's judgment was correct" is deliberately left to you: the receipt
contains the raw challenge and every check applied to it, so you can re-derive
the score from the receipt's own contents — or probe the endpoint yourself
and compare.

## Reporting a discrepancy

If any check fails, we want to know — open an issue on this repository. A verification
procedure nobody runs is theatre; a failure someone finds is a bug we fix in
public.
