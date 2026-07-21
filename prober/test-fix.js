'use strict';

/**
 * OFFLINE fixture test for the D1 / D2 / hash fix.
 *
 * No network. No DB. No receipts written. Stubs global.fetch so probe() runs
 * against canned 402 responses.
 *
 * Run:  node test-fix.js
 *
 * ---------------------------------------------------------------------------
 * FIXTURE PROVENANCE
 * V2_CHALLENGE is the REAL decoded PAYMENT-REQUIRED header captured from
 * https://x402.agentutility.ai/defi-llama on 2026-07-21.
 *
 * One honest caveat: the fixture re-encodes this object to base64 rather than
 * replaying the server's original header bytes, so key order and whitespace
 * may differ from the wire. That is immaterial to what these tests assert
 * (sourcing, leg selection, digest distinctness) but it does mean the digest
 * produced here is NOT the digest a live probe of this endpoint will produce.
 * Live digests are computed over the header exactly as received — which is
 * the correct behaviour and is what probe.js does.
 * ---------------------------------------------------------------------------
 */

const assert = require('node:assert');
const crypto = require('node:crypto');

const { probe, selectAccept, decodePaymentRequiredHeader, looksLikeChallenge } = require('./probe');
const { buildReceipt, scoreObservation } = require('./receipt');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// --- fixtures --------------------------------------------------------------

// Body-canonical, Solana-single — models a SolSigs endpoint (backward compat).
const V1_BODY_CHALLENGE = {
  x402Version: 1,
  accepts: [{
    scheme: 'exact',
    network: 'solana-mainnet',
    payTo: 'HZAkkKbhN9hfJBiNxCuwap7XtPXgniy9MVjJR2MvHSJi',
    asset: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
    maxAmountRequired: '2000',
    maxTimeoutSeconds: 60,
    resource: 'https://solsigs.com/dex',
    extra: { name: 'USDC', decimals: 6 },
  }],
};

// REAL vector: decoded PAYMENT-REQUIRED header captured from
// https://x402.agentutility.ai/defi-llama on 2026-07-21.
// Base (eip155:8453) is listed FIRST, Solana SECOND — this is exactly the
// shape that made the pre-fix prober grade a Solana seller on its Base leg.
// Note: `extensions` (bazaar schema, builder-code) is present on the wire and
// retained here verbatim so the fixture stays faithful.
const V2_CHALLENGE = {
  x402Version: 2,
  error: 'Payment required',
  resource: {
    url: 'https://x402.agentutility.ai/defi-llama',
    description: 'DefiLlama API / DeFi TVL protocol lookup. Resolves a DefiLlama protocol slug such as aave, lido, uniswap, makerdao, or curve-dex and returns current TVL, chain breakdown, protocol metadata, audit links, and optional historical TVL series.',
    mimeType: 'application/json',
    serviceName: 'AgentUtility.ai',
    tags: ['edge-market', 'defi', 'llama'],
    iconUrl: 'https://agentutility.ai/icon-512.png',
  },
  accepts: [
    {
      scheme: 'exact',
      network: 'eip155:8453',
      amount: '20000',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      payTo: '0x6c0752c09e7F6fA6526fCDf40e456a159ebB5621',
      maxTimeoutSeconds: 300,
      extra: { name: 'USD Coin', version: '2' },
    },
    {
      scheme: 'exact',
      network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
      amount: '20000',
      asset: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
      payTo: 'FJqAJ4dXkFbrp3EEo8E9x98iaBGUQwaU8Srz5ePfUXLH',
      maxTimeoutSeconds: 300,
      extra: { feePayer: 'BFK9TLC3edb13K6v4YyH3DwPb5DSUpkWvb7XnqCL9b4F' },
    },
  ],
};
const V2_HEADER_B64 = Buffer.from(JSON.stringify(V2_CHALLENGE)).toString('base64');

function stubFetch({ status = 402, body = '{}', headers = {} }) {
  global.fetch = async () => ({
    status,
    headers: { get: (k) => headers[k.toLowerCase()] ?? null },
    text: async () => body,
  });
}

// --- harness ---------------------------------------------------------------

let pass = 0, fail = 0;
async function t(name, fn) {
  try { await fn(); console.log(`  ok    ${name}`); pass++; }
  catch (e) { console.log(`  FAIL  ${name}\n        ${e.message}`); fail++; }
}

(async () => {
  console.log('\nD2 — leg selection (unit)');

  await t('picks the solana: leg, not accepts[0]', () => {
    const sel = selectAccept(V2_CHALLENGE.accepts);
    assert.strictEqual(sel.index, 1);
    assert.strictEqual(sel.solana_leg, true);
    assert.match(sel.accept.network, /^solana:/);
  });

  await t('falls back to accepts[0] when no solana leg', () => {
    const sel = selectAccept([{ network: 'eip155:8453' }, { network: 'eip155:1' }]);
    assert.strictEqual(sel.index, 0);
    assert.strictEqual(sel.solana_leg, false);
  });

  await t('matches bare v1 "solana-mainnet"', () => {
    const sel = selectAccept([{ network: 'eip155:8453' }, { network: 'solana-mainnet' }]);
    assert.strictEqual(sel.index, 1);
    assert.strictEqual(sel.solana_leg, true);
  });

  await t('empty / missing accepts is safe', () => {
    assert.strictEqual(selectAccept([]).accept, null);
    assert.strictEqual(selectAccept(undefined).accept, null);
  });

  console.log('\nD1 — challenge sourcing (unit)');

  await t('"{}" body is not treated as a challenge', () => {
    assert.strictEqual(looksLikeChallenge({}), false);
    assert.strictEqual(looksLikeChallenge(V2_CHALLENGE), true);
  });

  await t('header decodes to the challenge', () => {
    const d = decodePaymentRequiredHeader(V2_HEADER_B64);
    assert.strictEqual(d.x402Version, 2);
    assert.strictEqual(d.accepts.length, 2);
  });

  await t('garbage header decodes to null, does not throw', () => {
    assert.strictEqual(decodePaymentRequiredHeader('!!!not-base64!!!'), null);
    assert.strictEqual(decodePaymentRequiredHeader(null), null);
  });

  console.log('\nD1+D2 — v2 header-canonical seller end to end');

  stubFetch({ body: '{}', headers: { 'payment-required': V2_HEADER_B64, 'content-type': 'application/json' } });
  const v2obs = await probe({ url: 'https://x402.example.test/defi-llama', method: 'POST' });
  const v2rec = buildReceipt(v2obs);

  await t('challenge sourced from header', () => {
    assert.strictEqual(v2obs.challenge_source, 'header');
    assert.ok(v2obs.evidence_codes.includes('CHALLENGE_SOURCED_FROM_HEADER'));
  });

  await t('graded on the Solana leg', () => {
    assert.strictEqual(v2obs.accept_index, 1);
    assert.strictEqual(v2obs.solana_leg, true);
    assert.match(v2obs.accept_summary.network, /^solana:/);
    assert.strictEqual(v2obs.accept_summary.asset_is_mainnet_usdc, true);
  });

  await t('challenge is VALID (regression: previously scored 0/DENY)', () => {
    assert.strictEqual(v2obs.challenge_valid, true, `codes: ${v2obs.evidence_codes.join(', ')}`);
  });

  await t('score is real and non-zero, decision not DENY', () => {
    assert.ok(v2rec.trust_score.score > 50, `score=${v2rec.trust_score.score}`);
    assert.notStrictEqual(v2rec.trust_score.decision, 'DENY');
  });

  console.log('\nHASH — digest binds the real challenge bytes');

  await t('challenge hash = sha256(header), not sha256("{}")', () => {
    const h = v2rec.expectation_receipt.x402_payment_requirements_hash;
    assert.strictEqual(h, sha256(V2_HEADER_B64));
    assert.notStrictEqual(h, sha256('{}'));
  });

  await t('two header-canonical sellers do NOT collide', async () => {
    const other = JSON.parse(JSON.stringify(V2_CHALLENGE));
    other.accepts[1].payTo = 'So11111111111111111111111111111111111111112';
    const otherB64 = Buffer.from(JSON.stringify(other)).toString('base64');

    stubFetch({ body: '{}', headers: { 'payment-required': otherB64 } });
    const o2 = await probe({ url: 'https://other.example.test/x', method: 'POST' });
    const r2 = buildReceipt(o2);

    assert.notStrictEqual(
      r2.expectation_receipt.x402_payment_requirements_hash,
      v2rec.expectation_receipt.x402_payment_requirements_hash,
      'digests collided — the whole point of the hash fix'
    );
  });

  console.log('\nBACKWARD COMPAT — body-canonical Solana-single (own endpoints)');

  const v1body = JSON.stringify(V1_BODY_CHALLENGE);
  stubFetch({ body: v1body, headers: { 'content-type': 'application/json' } });
  const v1obs = await probe({ url: 'https://solsigs.com/dex', method: 'POST' });
  const v1rec = buildReceipt(v1obs);

  await t('still sourced from body', () => {
    assert.strictEqual(v1obs.challenge_source, 'body');
    assert.strictEqual(v1obs.accept_index, 0);
  });

  await t('digest UNCHANGED vs pre-fix behaviour (sha256 of body)', () => {
    assert.strictEqual(
      v1rec.expectation_receipt.x402_payment_requirements_hash,
      sha256(v1body),
      'body-canonical digests must not move, or historical receipts stop comparing'
    );
  });

  await t('scores 95 (one WARN: no PAYMENT-REQUIRED header on v1)', () => {
    assert.strictEqual(v1rec.trust_score.score, 95,
      `score=${v1rec.trust_score.score} codes=${v1obs.evidence_codes.join(', ')}`);
  });

  console.log('\nDEGRADED — genuinely broken seller must still hard-fail');

  stubFetch({ body: '{}', headers: {} });   // empty body AND no header
  const badObs = await probe({ url: 'https://broken.example.test/x', method: 'POST' });
  const badRec = buildReceipt(badObs);

  await t('no challenge anywhere -> invalid, low score (no regression)', () => {
    assert.strictEqual(badObs.challenge_valid, false);
    assert.ok(badRec.trust_score.score <= 5, `score=${badRec.trust_score.score}`);
  });

  stubFetch({ body: 'not json at all', headers: {} });
  const njObs = await probe({ url: 'https://broken2.example.test/x', method: 'POST' });
  await t('non-JSON body still FAIL_CHALLENGE_NOT_JSON', () => {
    assert.ok(njObs.evidence_codes.includes('FAIL_CHALLENGE_NOT_JSON'));
  });

  console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'}  ${pass} passed, ${fail} failed\n`);
  process.exit(fail === 0 ? 0 : 1);
})();
