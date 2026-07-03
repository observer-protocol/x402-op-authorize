// THE demo: one 24-hour budget, two rails, deny at the key.
//
// A principal signs ONE delegation: $5 per rolling 24h, spendable as USDC on
// Base (x402) or sats over Lightning (L402), at rates the principal attested
// inside the credential. Both buyer gates share ONE ledger file. The budget is
// consumed across rails until exactly exhausted — then BOTH rails refuse:
// the x402 payment dies at the signer (no EIP-3009 signature ever exists) and
// the Lightning payment dies at the pre-payment hook (lnget never pays).
//
// The x402 legs run against Cloudflare's UNMODIFIED x402-proxy-template on
// wrangler dev, with real EIP-712 signature verification at the facilitator
// (settlement simulated — no funded testnet wallet required; see
// harness/local-facilitator.mjs). The Lightning legs run through
// l402-op-authorize's real pre-payment hook on a synthetic invoice (the same
// gate lnget calls in production; no LND node required).
//
// Prerequisites (see harness/README): wrangler dev on :8787 + local
// facilitator on :4021.
//
// Usage: node demo/cross-rail.mjs
import { mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createPaymentHeader } from 'x402/client';
import { createObserverX402Account, ObserverDenyError } from '../dist/index.mjs';
import { CrossRailLedger, formatBudgetUnits } from '@observer-protocol/policy-engine';
import { makeAgent, issueVac, policyConfig } from '../test/fixtures/gen.mjs';

const SERVER_URL = process.env.SERVER_URL || 'http://127.0.0.1:8787';
const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, 'out');
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

const B = '\x1b[1m', G = '\x1b[32m', R = '\x1b[31m', D = '\x1b[2m', X = '\x1b[0m';
let failures = 0;
const expect = (name, ok, detail = '') => {
  console.log(`   ${ok ? G + '✓' : R + '✗'}${X} ${name}${!ok && detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
};

// ── Health checks ──────────────────────────────────────────────────────────
const health = await fetch(`${SERVER_URL}/__x402/health`).then((r) => r.json()).catch(() => null);
if (!health || health.status !== 'ok') {
  console.error(`Cloudflare x402-proxy-template not reachable at ${SERVER_URL} — start it first (see harness/README.md)`);
  process.exit(2);
}

// ── ONE delegation, ONE budget, TWO rails ──────────────────────────────────
const principal = makeAgent();
const agent = makeAgent();
const PAY_TO = '0x000000000000000000000000000000000000dEaD';
const RATES = { USDC: '1', sat: '0.0005' };
const mandate = issueVac({
  issuerDid: principal.did, issuerPriv: principal.privateKey, issuerVm: principal.vm,
  subjectDid: agent.did,
  actionScope: { allowed_rails: ['eip155:84532', 'lightning'] },
  tradingMandate: {
    counterparty: { allowList: [PAY_TO, 'api.example.com'] },
    crossRailBudget: { amount: '5', currency: 'USD', window: 'P1D', rates: RATES },
  },
});
const credPath = join(out, 'agent-delegation.json');
writeFileSync(credPath, JSON.stringify(mandate, null, 2));
const policy = policyConfig(principal.did, agent.did, out, credPath);
const ledgerPath = join(out, 'cross-rail-ledger.jsonl');
const ledger = new CrossRailLedger(ledgerPath);
const total = () => {
  const s = ledger.sumWindowConverted(RATES);
  return s.ok ? formatBudgetUnits(s.total) : `<unestablishable: ${s.reason}>`;
};

// x402 buyer: real viem account wrapped by OP, handed to the unmodified x402 client.
const account = createObserverX402Account(privateKeyToAccount(generatePrivateKey()), {
  policy, crossRailLedgerPath: ledgerPath,
});
// Lightning buyer: the real l402-op-authorize pre-payment hook (what lnget calls).
const { handleL402PaymentHook } = await import('@observer-protocol/l402-op-authorize');

console.log(`${B}Observer Protocol — one budget, two rails, deny at the key${X}`);
console.log(`${D}principal ${principal.did.slice(0, 38)}…${X}`);
console.log(`${D}agent     ${agent.did.slice(0, 38)}…  wallet ${account.address}${X}`);
console.log(`mandate: ${B}$5.00 / rolling 24h across ALL rails${X} — rates attested in the signed credential (USDC=1, sat=0.0005); no oracle anywhere in the flow\n`);

async function x402Pay(label) {
  const c = await fetch(`${SERVER_URL}/__x402/protected`);
  const challenge = await c.json();
  const header = await createPaymentHeader(account, challenge.x402Version, challenge.accepts[0]);
  const paid = await fetch(`${SERVER_URL}/__x402/protected`, { headers: { 'X-PAYMENT': header } });
  return { challengeStatus: c.status, paidStatus: paid.status, receipt: paid.headers.get('x-payment-response') };
}
async function lightningPay(label, invoice) {
  return handleL402PaymentHook(policy, { origin: 'https://api.example.com/data', invoice, crossRailLedgerPath: ledgerPath });
}

// A ── x402: $0.01 USDC on Base Sepolia via the Cloudflare template
console.log(`${B}A. x402 rail — $0.01 USDC via Cloudflare x402-proxy-template${X}`);
const a = await x402Pay('A');
expect('402 challenged, OP allowed, EIP-3009 signed, template returned 200', a.challengeStatus === 402 && a.paidStatus === 200 && !!a.receipt, JSON.stringify(a));
console.log(`   ${D}budget consumed: ${total()} of 5 USD${X}\n`);

// B ── Lightning: 9940 sats (= $4.97) through the l402 pre-payment hook
console.log(`${B}B. Lightning rail — 9940-sat L402 invoice ($4.97) via l402-op-authorize hook${X}`);
const b = await lightningPay('B', 'lnbc99400n1x');
expect('hook allowed the payment and recorded it in the SAME ledger', b.decision === 'allow', b.reason);
console.log(`   ${D}budget consumed: ${total()} of 5 USD${X}\n`);

// C, D ── two more x402 cents: land exactly on the cap
console.log(`${B}C+D. x402 rail — two more $0.01 payments (budget reaches exactly $5.00)${X}`);
const cRes = await x402Pay('C');
expect('C allowed (4.99)', cRes.paidStatus === 200);
const dRes = await x402Pay('D');
expect('D allowed (5.00 — budget exactly consumed, ≤ cap holds)', dRes.paidStatus === 200);
console.log(`   ${D}budget consumed: ${total()} of 5 USD${X}\n`);

// E ── x402 attempt: DENIED AT THE KEY
console.log(`${B}E. x402 rail — next $0.01 → DENY AT THE KEY${X}`);
let eErr;
try { await x402Pay('E'); } catch (err) { eErr = err; }
expect('ObserverDenyError thrown INSIDE the unmodified x402 client', eErr instanceof ObserverDenyError, String(eErr));
expect('reason: cross-rail budget', (eErr?.reason ?? '').includes('[cross-rail]'));
console.log(`   ${D}${eErr?.reason}${X}`);
const still402 = await fetch(`${SERVER_URL}/__x402/protected`);
expect('no signature exists → nothing settled → resource still 402', still402.status === 402, `got ${still402.status}`);
console.log();

// F ── Lightning attempt: DENIED AT THE HOOK
console.log(`${B}F. Lightning rail — 200-sat invoice ($0.10) → DENY AT THE HOOK${X}`);
const f = await lightningPay('F', 'lnbc2u1x');
expect('hook denied from the same shared budget', f.decision === 'deny' && f.reason.includes('[cross-rail]'), f.reason);
console.log(`   ${D}${f.reason}${X}\n`);

// ── Decision proof ─────────────────────────────────────────────────────────
console.log(`${B}Decision log (append-only, one line per verdict)${X}`);
for (const line of readFileSync(join(out, 'decisions.jsonl'), 'utf8').trim().split('\n')) {
  const e = JSON.parse(line);
  console.log(`   ${e.decision === 'allow' ? G + 'ALLOW' : R + 'DENY '}${X} ${(e.kind ?? '').padEnd(12)} ${e.reason.slice(0, 100)}`);
}
console.log(`${B}Shared cross-rail ledger${X} (${ledgerPath.replace(here + '/', 'demo/')})`);
for (const line of readFileSync(ledgerPath, 'utf8').trim().split('\n')) {
  const e = JSON.parse(line);
  console.log(`   ${D}${e.rail.padEnd(18)} ${e.amountRaw.padStart(8)} ${e.asset}${X}`);
}

console.log(`\n${failures === 0 ? G + B + 'DEMO GREEN' : R + B + 'DEMO RED'}${X} — one signed mandate, one 24h budget, USDC-on-Base + Lightning, over-budget attempts denied at the key (x402) and at the hook (L402).`);
process.exit(failures === 0 ? 0 : 1);
