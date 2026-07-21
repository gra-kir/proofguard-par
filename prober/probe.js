'use strict';

/**
 * ProofGuard independent prober — unpaid 402-level probe of an x402 endpoint.
 *
 * Sends a request WITHOUT payment, captures the HTTP 402 challenge, and
 * validates it against x402 v2 spec-level checks. No payment is ever made.
 *
 * NOTE: the check set below mirrors the spec-level checks used by the
 * SolSigs validator (validate-router.js, spec authority x402-foundation/x402
 * protocol V2, confirmed via VPS discovery 2026-07-01). It is implemented
 * independently here because the prober must never import from the
 * x402-swarm request path. Version-aware like the validator: V2 bodies get
 * CAIP-2 network enforcement, top-level ResourceInfo, and the normative
 * PAYMENT-REQUIRED header check; V1 bodies get the permissive variants.
 */

const { URL } = require('node:url');

const USDC_MAINNET = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

// CAIP-2 per x402 V2 §11.1: namespace:reference
const CAIP2_RE = /^[a-z][a-z0-9-]*:[A-Za-z0-9][A-Za-z0-9-]*$/;

/**
 * Does a parsed object look like an x402 challenge (rather than an empty or
 * unrelated body)? V2 header-canonical sellers return `{}` as the body and put
 * the real challenge in the base64 PAYMENT-REQUIRED header.
 */
function looksLikeChallenge(o) {
  return Boolean(
    o && typeof o === 'object' && !Array.isArray(o) &&
    (typeof o.x402Version === 'number' || Array.isArray(o.accepts))
  );
}

/** Decode the base64 PAYMENT-REQUIRED header into a challenge object, or null. */
function decodePaymentRequiredHeader(prHeader) {
  if (!prHeader || typeof prHeader !== 'string') return null;
  try {
    const decoded = JSON.parse(Buffer.from(prHeader, 'base64').toString('utf8'));
    return looksLikeChallenge(decoded) ? decoded : null;
  } catch {
    return null;
  }
}

/**
 * Select which accepts[] leg to grade. ProofGuard is the Solana trust layer,
 * so a multi-chain seller must be graded on its Solana leg — not on whichever
 * leg happens to be listed first (commonly Base / eip155:8453).
 * Falls back to accepts[0] when no Solana leg is present.
 */
function selectAccept(accepts) {
  if (!Array.isArray(accepts) || accepts.length === 0) {
    return { accept: null, index: null, solana_leg: false };
  }
  // V2: CAIP-2 "solana:<genesis-hash-prefix>"
  let i = accepts.findIndex((a) => typeof a?.network === 'string' && /^solana:/i.test(a.network));
  if (i >= 0) return { accept: accepts[i], index: i, solana_leg: true };
  // V1 permissive: bare "solana" / "solana-mainnet"
  i = accepts.findIndex((a) => typeof a?.network === 'string' && /^solana(-|$)/i.test(a.network));
  if (i >= 0) return { accept: accepts[i], index: i, solana_leg: true };
  return { accept: accepts[0], index: 0, solana_leg: false };
}

function isPrivateHost(hostname) {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return true;
  // IPv4 literals
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  }
  // IPv6 loopback / link-local / unique-local
  if (h === '::1' || h.startsWith('fe80:') || h.startsWith('fc') || h.startsWith('fd') || h === '::') return true;
  return false;
}

/** Validate a probe target URL. Rejects non-HTTPS and private/loopback hosts. */
function validateTargetUrl(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return { ok: false, reason: 'TARGET_URL_INVALID' };
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    return { ok: false, reason: 'TARGET_SCHEME_UNSUPPORTED' };
  }
  if (process.env.ALLOW_LOCAL !== '1' && isPrivateHost(u.hostname)) {
    return { ok: false, reason: 'TARGET_PRIVATE_HOST_REJECTED' };
  }
  return { ok: true, url: u };
}

/**
 * Spec-level checks applied to the 402 challenge.
 * Each check: { code, level(ctx): 'fail'|'warn', test(ctx) -> bool (true = pass) }
 * ctx = { body, accept, target, isV2, prHeader }
 * fail => challenge invalid; warn => recorded, small score deduction.
 */
const CHECKS = [
  { code: 'X402_VERSION_PRESENT', level: () => 'fail', test: ({ body: b }) => b.x402Version === 1 || b.x402Version === 2 },
  { code: 'ACCEPTS_ARRAY_PRESENT', level: () => 'fail', test: ({ body: b }) => Array.isArray(b.accepts) && b.accepts.length > 0 },
  { code: 'SCHEME_PRESENT', level: () => 'fail', test: ({ accept: a }) => a && typeof a.scheme === 'string' && a.scheme.length > 0 },
  {
    // V2 §11.1: network MUST be CAIP-2 namespace:reference. V1: permissive.
    code: 'NETWORK_VALID', level: () => 'fail',
    test: ({ accept: a, isV2 }) => {
      const net = String(a?.network || '');
      if (!net) return false;
      return isV2 ? CAIP2_RE.test(net) : /solana|base|polygon|avalanche|sei|ethereum|^eip155:|^solana:/i.test(net);
    },
  },
  { code: 'PAY_TO_PRESENT', level: () => 'fail', test: ({ accept: a }) => a && typeof a.payTo === 'string' && a.payTo.length >= 32 },
  { code: 'ASSET_PRESENT', level: () => 'fail', test: ({ accept: a }) => a && typeof a.asset === 'string' && a.asset.length > 0 },
  {
    // V2 field is `amount`; V1 is `maxAmountRequired`. Accept either, require atomic-unit string.
    code: 'AMOUNT_ATOMIC_STRING', level: () => 'fail',
    test: ({ accept: a }) => {
      const v = a?.amount ?? a?.maxAmountRequired;
      return typeof v === 'string' && /^\d+$/.test(v);
    },
  },
  {
    // V2 §5.1.2: top-level body.resource ResourceInfo. V1: accepts[0].resource.
    code: 'RESOURCE_PRESENT', level: () => 'warn',
    test: ({ body: b, accept: a, isV2 }) => isV2
      ? Boolean(b.resource && typeof b.resource === 'object' && typeof b.resource.url === 'string' && b.resource.url.length > 0)
      : typeof a?.resource === 'string' && a.resource.length > 0,
  },
  {
    code: 'RESOURCE_HTTPS', level: () => 'warn',
    test: ({ body: b, accept: a }) => {
      const r = (b.resource && b.resource.url) || (a && a.resource) || '';
      return typeof r === 'string' && r.length > 0 ? r.startsWith('https://') : true;
    },
  },
  { code: 'TIMEOUT_DECLARED', level: () => 'warn', test: ({ accept: a }) => a && Number(a.maxTimeoutSeconds) > 0 },
  {
    // V2 transports-v2/http.md: canonical wire location is the base64
    // PAYMENT-REQUIRED header. Normative for V2, forward-compat warn for V1.
    code: 'PAYMENT_REQUIRED_HEADER', level: ({ isV2 }) => (isV2 ? 'fail' : 'warn'),
    test: ({ prHeader }) => {
      if (!prHeader) return false;
      try {
        const decoded = JSON.parse(Buffer.from(prHeader, 'base64').toString('utf8'));
        return decoded !== null && typeof decoded === 'object';
      } catch {
        return false;
      }
    },
  },
  {
    code: 'EXPECTED_PAY_TO_MATCH', level: () => 'warn',
    test: ({ accept: a, target: t }) => !t.expected_pay_to || (a && a.payTo === t.expected_pay_to),
  },
  {
    code: 'EXPECTED_NETWORK_MATCH', level: () => 'warn',
    test: ({ accept: a, target: t }) => !t.expected_network || (a && a.network === t.expected_network),
  },
];

/**
 * Perform an unpaid probe of one target.
 * @param {{url: string, method?: string, expected_pay_to?: string, expected_network?: string}} target
 * @param {{timeout_ms?: number, max_latency_ms?: number}} opts
 * @returns {Promise<object>} raw probe observation (feed into receipt.js)
 */
async function probe(target, opts = {}) {
  const timeoutMs = opts.timeout_ms ?? 15000;
  const maxLatencyMs = opts.max_latency_ms ?? 5000;
  const method = (target.method || 'POST').toUpperCase();
  const probedAt = new Date().toISOString();

  const observation = {
    target_url: target.url,
    method,
    probed_at: probedAt,
    reachable: false,
    status: null,
    latency_ms: null,
    challenge_valid: false,
    checks: {},
    evidence_codes: [],
    headers: {},
    accept_summary: null,
    // D1: where the challenge was actually sourced from, and the exact bytes
    // that were graded. challenge_raw is what receipt.js hashes — hashing the
    // response body collides across every header-canonical seller (all "{}").
    challenge_source: null,
    challenge_raw: null,
    // D2: which accepts[] leg was graded, and whether it was the Solana one.
    accept_index: null,
    solana_leg: false,
    error: null,
  };

  const v = validateTargetUrl(target.url);
  if (!v.ok) {
    observation.evidence_codes.push(v.reason);
    return observation;
  }

  const started = process.hrtime.bigint();
  let res;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    res = await fetch(target.url, {
      method,
      headers: { 'content-type': 'application/json', 'user-agent': 'SolSigs-ProofGuard-Prober/0.1' },
      body: method === 'GET' || method === 'HEAD' ? undefined : '{}',
      redirect: 'manual',
      signal: controller.signal,
    });
    clearTimeout(timer);
  } catch (err) {
    observation.latency_ms = Math.round(Number(process.hrtime.bigint() - started) / 1e6);
    observation.error = err.cause?.code || err.name || String(err.message).slice(0, 200);
    observation.evidence_codes.push('PROBE_UNREACHABLE');
    return observation;
  }
  observation.latency_ms = Math.round(Number(process.hrtime.bigint() - started) / 1e6);
  observation.reachable = true;
  observation.status = res.status;

  for (const h of ['cache-control', 'age', 'date', 'content-type', 'expires', 'last-modified']) {
    const val = res.headers.get(h);
    if (val !== null) observation.headers[h] = val;
  }
  const prHeader = res.headers.get('payment-required');
  observation.headers['payment-required'] = prHeader ? '<present>' : undefined;

  const rawBody = await res.text().catch(() => '');
  observation.response_body = rawBody.slice(0, 8192);

  if (res.status !== 402) {
    observation.evidence_codes.push('FAIL_NOT_402');
    return observation;
  }
  observation.evidence_codes.push('PROBE_402_RECEIVED');

  // --- D1: challenge sourcing -------------------------------------------
  // Order: a body that actually looks like a challenge wins; otherwise fall
  // back to the base64 PAYMENT-REQUIRED header (V2 canonical wire location);
  // otherwise keep the parsed body so the CHECKS below still hard-fail it
  // exactly as before this fix.
  let parsedBody = null;
  try {
    parsedBody = JSON.parse(rawBody);
  } catch {
    observation.evidence_codes.push('FAIL_CHALLENGE_NOT_JSON');
    return observation;
  }

  let body;
  const fromHeader = decodePaymentRequiredHeader(prHeader);
  if (looksLikeChallenge(parsedBody)) {
    body = parsedBody;
    observation.challenge_source = 'body';
    // Same slice that was hashed before this fix -> digests for existing
    // body-canonical targets are unchanged.
    observation.challenge_raw = observation.response_body;
  } else if (fromHeader) {
    body = fromHeader;
    observation.challenge_source = 'header';
    // Canonical wire form: the base64 header exactly as received.
    observation.challenge_raw = prHeader;
    observation.evidence_codes.push('CHALLENGE_SOURCED_FROM_HEADER');
  } else {
    body = parsedBody;
    observation.challenge_source = 'body';
    observation.challenge_raw = observation.response_body;
  }

  // --- D2: leg selection --------------------------------------------------
  const sel = selectAccept(body.accepts);
  const accept = sel.accept;
  observation.accept_index = sel.index;
  observation.solana_leg = sel.solana_leg;
  if (Array.isArray(body.accepts) && body.accepts.length > 1 && !sel.solana_leg) {
    observation.evidence_codes.push('WARN_NO_SOLANA_LEG');
  }

  const isV2 = typeof body.x402Version === 'number' ? body.x402Version >= 2 : false;
  observation.spec_version = `x402v${typeof body.x402Version === 'number' ? body.x402Version : 1}`;
  const ctx = { body, accept, target, isV2, prHeader };
  let hardFail = false;
  for (const check of CHECKS) {
    let pass = false;
    try { pass = Boolean(check.test(ctx)); } catch { pass = false; }
    const level = check.level(ctx);
    observation.checks[check.code] = pass;
    if (!pass) {
      observation.evidence_codes.push(`${level === 'fail' ? 'FAIL' : 'WARN'}_${check.code}`);
      if (level === 'fail') hardFail = true;
    }
  }

  if (observation.latency_ms > maxLatencyMs) {
    observation.evidence_codes.push('WARN_LATENCY_EXCEEDED');
  }

  observation.challenge_valid = !hardFail;
  if (observation.challenge_valid) observation.evidence_codes.push('CHALLENGE_SPEC_VALID');

  if (accept) {
    observation.accept_summary = {
      scheme: accept.scheme ?? null,
      network: accept.network ?? null,
      payTo: accept.payTo ?? null,
      asset: accept.asset ?? null,
      maxAmountRequired: accept.maxAmountRequired ?? accept.amount ?? null,
      currency: accept.extra?.name ?? null,
      decimals: accept.extra?.decimals ?? null,
      maxTimeoutSeconds: accept.maxTimeoutSeconds ?? null,
      asset_is_mainnet_usdc: accept.asset === USDC_MAINNET,
    };
  }

  return observation;
}

module.exports = {
  probe,
  validateTargetUrl,
  CHECKS,
  looksLikeChallenge,
  decodePaymentRequiredHeader,
  selectAccept,
};
