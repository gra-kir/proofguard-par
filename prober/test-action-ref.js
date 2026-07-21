'use strict';

/**
 * OFFLINE conformance test for action_ref emission in PAR receipts.
 *
 * Vectors 1 and 2 are byte-verified examples published in
 * argentum-core docs/spec/action-ref.md v1.1 — if we reproduce their exact
 * digests, our derivation is conformant with the ecosystem's (AGT
 * EvidenceAnchor SPI, SafeAgent, Nobulex, CrewAI all converge on it).
 *
 * No network. No DB. fetch is stubbed.   Run: node test-action-ref.js
 */

const assert = require('node:assert');
const { probe } = require('./probe');
const { buildReceipt, computeActionRef, buildActionRefEnvelope } = require('./receipt');

let pass = 0, fail = 0;
async function t(name, fn) {
  try { await fn(); console.log(`  ok    ${name}`); pass++; }
  catch (e) { console.log(`  FAIL  ${name}\n        ${e.message}`); fail++; }
}

(async () => {
  console.log('\nCONFORMANCE — spec byte-verified vectors');

  await t('NEXUS oracle vector reproduces exactly', () => {
    const ref = computeActionRef(
      'nexus-agent-xa12.onrender.com', 'oracle.signal', 'BTC', '2025-05-18T11:40:31.000Z');
    assert.strictEqual(ref, 'fdd7f810499f06be24355ca8e2bfb8c4b965cc80c838f41fa074683443d89f5a');
  });

  await t('memory_write vector reproduces exactly', () => {
    const ref = computeActionRef(
      'giskard-self', 'memory_write', 'mycelium:memory:session_context_v3', '2026-05-26T20:15:00.000Z');
    assert.strictEqual(ref, '36fe8d0559bb254c20cdb0e7a0c83e53f0434fc076e856ff769444da2a73b0b4');
  });

  console.log('\nPROFILE DOMAIN — non-conformant inputs refused, not fudged');

  await t('timestamp without ms → null (out of profile domain)', () => {
    assert.strictEqual(computeActionRef('a', 'b', 'c', '2026-05-15T10:00:00Z'), null);
  });
  await t('timestamp with +00:00 offset → null', () => {
    assert.strictEqual(computeActionRef('a', 'b', 'c', '2026-05-15T10:00:00.123+00:00'), null);
  });
  await t('epoch-ms integer passed as string → null', () => {
    assert.strictEqual(computeActionRef('a', 'b', 'c', '1747568431000'), null);
  });

  console.log('\nINTEGRATION — envelope inside a real probe receipt');

  const CHALLENGE = JSON.stringify({
    x402Version: 1,
    accepts: [{ scheme: 'exact', network: 'solana-mainnet',
      payTo: 'HZAkkKbhN9hfJBiNxCuwap7XtPXgniy9MVjJR2MvHSJi',
      asset: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
      maxAmountRequired: '2000', maxTimeoutSeconds: 60,
      resource: 'https://solsigs.com/dex', extra: { name: 'USDC', decimals: 6 } }],
  });
  global.fetch = async () => ({
    status: 402,
    headers: { get: (k) => (k.toLowerCase() === 'content-type' ? 'application/json' : null) },
    text: async () => CHALLENGE,
  });
  const obs = await probe({ url: 'https://solsigs.com/dex', method: 'POST' });
  const receipt = buildReceipt(obs);
  const env = receipt.action_ref_envelope;

  await t('envelope present with all v1.0 fields', () => {
    assert.ok(env, 'envelope missing');
    assert.strictEqual(env.packet_version, '1.0');
    assert.strictEqual(env.hash_algo, 'sha256');
    assert.strictEqual(env.preimage_format, 'jcs-rfc8785-v1');
    assert.strictEqual(env.preimage.action_type, 'x402.probe');
    assert.match(env.preimage.scope, /^proofguard:x402\.probe:https:\/\/solsigs\.com\/dex$/);
  });

  await t('probed_at is profile-conformant (toISOString form)', () => {
    assert.match(env.preimage.timestamp, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    assert.strictEqual(env.preimage.timestamp, obs.probed_at);
  });

  await t('action_ref independently recomputable from preimage alone', () => {
    // The property the whole standard exists for: a stranger holding only
    // the four preimage fields reproduces the ref without trusting us.
    const crypto = require('node:crypto');
    const p = env.preimage;
    const canonical = JSON.stringify({
      action_type: p.action_type, agent_id: p.agent_id, scope: p.scope, timestamp: p.timestamp,
    });
    const independent = crypto.createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('hex');
    assert.strictEqual(independent, env.action_ref);
  });

  await t('same action instance → same ref; different target → different ref', () => {
    const again = buildActionRefEnvelope(obs);
    assert.strictEqual(again.action_ref, env.action_ref);
    const other = buildActionRefEnvelope({ ...obs, target_url: 'https://solsigs.com/arb' });
    assert.notStrictEqual(other.action_ref, env.action_ref);
  });

  await t('receipt_hash still computes and covers the envelope', () => {
    assert.match(receipt.receipt_hash, /^[0-9a-f]{64}$/);
    // Envelope is inside the hashed body: tampering with it must break the hash.
    const { sha256Hex, canonicalJson } = require('./receipt');
    const tampered = JSON.parse(JSON.stringify(receipt));
    delete tampered.receipt_hash;
    tampered.action_ref_envelope.action_ref = '0'.repeat(64);
    assert.notStrictEqual(sha256Hex(canonicalJson(tampered)), receipt.receipt_hash);
  });

  console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'}  ${pass} passed, ${fail} failed\n`);
  process.exit(fail === 0 ? 0 : 1);
})();
