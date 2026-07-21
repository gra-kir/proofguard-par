'use strict';
const { probe } = require('./probe');
const { buildReceipt } = require('./receipt');
async function main() {
  const argv = process.argv.slice(2);
  let method = 'POST';
  if (argv[0] && /^(GET|POST|HEAD|PUT|PATCH|DELETE)$/i.test(argv[0])) {
    method = argv.shift().toUpperCase();
  }
  const urls = argv;
  if (urls.length === 0) { console.error('give URL(s)'); process.exit(1); }
  for (const url of urls) {
    const obs = await probe({ url, method });
    const receipt = buildReceipt(obs);
    const net = obs.accept_summary ? obs.accept_summary.network : null;
    const usdc = obs.accept_summary ? obs.accept_summary.asset_is_mainnet_usdc : null;
    console.log(`\n${obs.challenge_valid ? 'PASS' : 'FAIL'}  ${String(obs.status ?? 'ERR').padEnd(4)} ${String(obs.latency_ms ?? '-').padStart(6)}ms  score=${String(receipt.trust_score.score).padStart(3)} ${receipt.trust_score.decision.padEnd(17)} ${url}`);
    console.log(`   spec=${obs.spec_version ?? '-'}  network=${net ?? '-'}  mainnet_usdc=${usdc}`);
    console.log(`   codes: ${obs.evidence_codes.join(', ')}`);
  }
  console.log('\n(read-only — no receipt written, DB untouched)');
}
main().catch((e) => { console.error(e); process.exit(1); });
