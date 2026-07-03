// THE demo: one 24-hour budget, three rails, denied on every rail.
//
// A principal signs ONE delegation: $5 per rolling 24h, spendable as USDC on
// Base (x402), sats over Lightning (L402), or USDT on TRON (Tether WDK), at
// rates the principal attested inside the credential. Three independent OP
// buyer gates share ONE ledger file. The budget is consumed across all three
// rails until exactly exhausted — then EVERY rail refuses: the x402 payment
// dies at the signer (no EIP-3009 signature ever exists), the Lightning
// payment dies at the lnget pre-payment hook, and the TRON transfer dies
// inside Tether's own WDK policy engine (fail-closed DENY rule).
//
// Fidelity, stated plainly:
//   x402   — Cloudflare's UNMODIFIED x402-proxy-template on wrangler dev; the
//            real x402@1.0.1 client signs; real EIP-712 verification at the
//            facilitator. Settlement is REAL (on-chain Base Sepolia USDC via
//            the x402.org facilitator, buyer holds zero ETH — EIP-3009 is
//            payer-gasless) when .dev.vars omits FACILITATOR_URL; simulated
//            when pointed at harness/local-facilitator.mjs.
//   L402   — l402-op-authorize's real pre-payment hook (what lnget calls in
//            production) on a synthetic invoice; no LND node.
//   TRON   — the REAL merged WDK policy engine (PR #55) + applyPoliciesTo
//            proxy + the real OP ALLOW/DENY condition pair, on a mock TRON
//            account; no chain broadcast (same fidelity as the wdk-op-policy
//            conformance suite).
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
import { buildObserverPolicies } from '@observer-protocol/wdk-op-policy';
import { makeAgent, issueVac, policyConfig } from '../test/fixtures/gen.mjs';
// The real WDK policy engine (a devDependency of the wdk-op-policy engine repo).
import PolicyEngine from '../../wdk-op-policy/node_modules/@tetherto/wdk/src/policy/policy-engine.js';
import PolicyViolationError from '../../wdk-op-policy/node_modules/@tetherto/wdk/src/policy/policy-error.js';

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

// ── ONE delegation, ONE budget, THREE rails ────────────────────────────────
const principal = makeAgent();
const agent = makeAgent();
const PAY_TO = '0x000000000000000000000000000000000000dEaD'; // template default PAY_TO
const USDT_TRC20 = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'; // mainnet USDT TRC-20 (6dec)
const TRON_MERCHANT = 'TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9';
// USDT is its OWN attested entry (explicitly "1") — no implicit peg-equivalence
// with USDC anywhere in the evaluator.
const RATES = { USDC: '1', USDT: '1', sat: '0.0005' };
const mandate = issueVac({
  issuerDid: principal.did, issuerPriv: principal.privateKey, issuerVm: principal.vm,
  subjectDid: agent.did,
  actionScope: { allowed_rails: ['eip155:84532', 'lightning', 'tron:mainnet'] },
  tradingMandate: {
    counterparty: { allowList: [PAY_TO, 'api.example.com', TRON_MERCHANT] },
    crossRailBudget: { amount: '5', currency: 'USD', window: 'P1D', rates: RATES },
  },
});
const credPath = join(out, 'agent-delegation.json');
writeFileSync(credPath, JSON.stringify(mandate, null, 2));
const policy = {
  ...policyConfig(principal.did, agent.did, out, credPath),
  rails: {
    'eip155:84532': { rail: 'base-sepolia', currency: 'ETH', decimals: 18, family: 'evm' },
    lightning: { rail: 'lightning', currency: 'sat', decimals: 0, family: 'other' },
    'tron:mainnet': { rail: 'usdt-trc20', currency: 'TRX', decimals: 6, family: 'other' },
  },
  trc20Tokens: { [USDT_TRC20]: { symbol: 'USDT', decimals: 6 } },
};
const ledgerPath = join(out, 'cross-rail-ledger.jsonl');
const ledger = new CrossRailLedger(ledgerPath);
const total = () => {
  const s = ledger.sumWindowConverted(RATES);
  return s.ok ? formatBudgetUnits(s.total) : `<unestablishable: ${s.reason}>`;
};

// Rail 1 buyer — x402: real viem account wrapped by OP, handed to the unmodified
// x402 client. Key resolution: PRIVATE_KEY env > the funded demo key in
// ~/.config/op-crossrail/demo-buyer.key > a fresh ephemeral key. The key file
// lives OUTSIDE the repo by standing policy — never in code or workspace files.
import { readFileSync as readKeyFile, existsSync as keyExists } from 'node:fs';
import { homedir } from 'node:os';
const KEY_FILE = join(homedir(), '.config/op-crossrail/demo-buyer.key');
const buyerKey = process.env.PRIVATE_KEY
  ?? (keyExists(KEY_FILE) ? readKeyFile(KEY_FILE, 'utf8').trim() : generatePrivateKey());
const account = createObserverX402Account(privateKeyToAccount(buyerKey), {
  policy, crossRailLedgerPath: ledgerPath,
});
// Rail 2 buyer — Lightning: the real l402-op-authorize pre-payment hook (what lnget calls).
const { handleL402PaymentHook } = await import('@observer-protocol/l402-op-authorize');
// Rail 3 buyer — TRON via Tether's WDK: the REAL merged policy engine + the OP
// ALLOW/DENY pair, governing a mock TRON account.
const wdkEngine = new PolicyEngine();
wdkEngine.register(
  buildObserverPolicies({ policy, wallets: { tron: 'tron:mainnet' }, crossRailLedgerPath: ledgerPath }, { wallet: 'tron' }),
  { conditionTimeoutMs: 5000 },
);
const tronCalls = { n: 0 };
const tronBase = {
  path: "0'/0/0",
  async toReadOnlyAccount() { return { getAddress: async () => 'TXAgentMockWa11etAddre55ooooooooooo' }; },
  transfer: async () => { tronCalls.n++; return { hash: 'MOCK-TRON-TX' }; },
  sendTransaction: async () => { tronCalls.n++; return { hash: 'MOCK-TRON-TX' }; },
};
const tron = await wdkEngine.applyPoliciesTo(tronBase, { blockchain: 'tron', path: tronBase.path, index: 0 });

console.log(`${B}Observer Protocol — one budget, three rails, denied on every rail${X}`);
console.log(`${D}principal ${principal.did.slice(0, 38)}…${X}`);
console.log(`${D}agent     ${agent.did.slice(0, 38)}…  EVM wallet ${account.address}${X}`);
console.log(`mandate: ${B}$5.00 / rolling 24h across ALL rails${X} — rates attested in the signed credential (USDC=1, USDT=1, sat=0.0005); no oracle anywhere in the flow\n`);

async function x402Pay() {
  const c = await fetch(`${SERVER_URL}/__x402/protected`);
  const challenge = await c.json();
  const header = await createPaymentHeader(account, challenge.x402Version, challenge.accepts[0]);
  const paid = await fetch(`${SERVER_URL}/__x402/protected`, { headers: { 'X-PAYMENT': header } });
  return { challengeStatus: c.status, paidStatus: paid.status, receipt: paid.headers.get('x-payment-response') };
}
const lightningPay = (invoice) =>
  handleL402PaymentHook(policy, { origin: 'https://api.example.com/data', invoice, crossRailLedgerPath: ledgerPath });
const usdtPay = (whole) =>
  tron.transfer({ token: USDT_TRC20, recipient: TRON_MERCHANT, amount: BigInt(Math.round(whole * 1e6)) });

// A ── x402: $0.01 USDC on Base Sepolia via the Cloudflare template
console.log(`${B}A. x402 rail — $0.01 USDC via Cloudflare x402-proxy-template${X}`);
const a = await x402Pay();
expect('402 challenged, OP allowed, EIP-3009 signed, template returned 200', a.challengeStatus === 402 && a.paidStatus === 200 && !!a.receipt, JSON.stringify(a));
console.log(`   ${D}budget consumed: ${total()} of 5 USD${X}\n`);

// B ── Lightning: 5940 sats (= $2.97) through the l402 pre-payment hook
console.log(`${B}B. Lightning rail — 5940-sat L402 invoice ($2.97) via l402-op-authorize hook${X}`);
const b = await lightningPay('lnbc59400n1x');
expect('hook allowed the payment and recorded it in the SAME ledger', b.decision === 'allow', b.reason);
console.log(`   ${D}budget consumed: ${total()} of 5 USD${X}\n`);

// C ── TRON: 2 USDT through Tether's own WDK policy engine
console.log(`${B}C. TRON rail — 2 USDT (TRC-20) via the real WDK policy engine${X}`);
const cRes = await usdtPay(2).then((r) => r, (e) => e);
expect('WDK engine allowed the transfer (OP ALLOW rule), spend recorded in the SAME ledger', cRes?.hash === 'MOCK-TRON-TX' && tronCalls.n === 1, String(cRes));
console.log(`   ${D}budget consumed: ${total()} of 5 USD${X}\n`);

// D, E ── two more x402 cents: land exactly on the cap
console.log(`${B}D+E. x402 rail — two more $0.01 payments (budget reaches exactly $5.00)${X}`);
const dRes = await x402Pay();
expect('D allowed (4.99)', dRes.paidStatus === 200);
const eRes = await x402Pay();
expect('E allowed (5.00 — budget exactly consumed, ≤ cap holds)', eRes.paidStatus === 200);
console.log(`   ${D}budget consumed: ${total()} of 5 USD${X}\n`);

// F ── x402 attempt: DENIED AT THE KEY
console.log(`${B}F. x402 rail — next $0.01 → DENY AT THE KEY${X}`);
let fErr;
try { await x402Pay(); } catch (err) { fErr = err; }
expect('ObserverDenyError thrown INSIDE the unmodified x402 client', fErr instanceof ObserverDenyError, String(fErr));
expect('reason: cross-rail budget', (fErr?.reason ?? '').includes('[cross-rail]'));
console.log(`   ${D}${fErr?.reason}${X}`);
const still402 = await fetch(`${SERVER_URL}/__x402/protected`);
expect('no signature exists → nothing settled → resource still 402', still402.status === 402, `got ${still402.status}`);
console.log();

// G ── Lightning attempt: DENIED AT THE HOOK
console.log(`${B}G. Lightning rail — 200-sat invoice ($0.10) → DENY AT THE HOOK${X}`);
const g = await lightningPay('lnbc2u1x');
expect('hook denied from the same shared budget', g.decision === 'deny' && g.reason.includes('[cross-rail]'), g.reason);
console.log(`   ${D}${g.reason}${X}\n`);

// H ── TRON attempt: DENIED INSIDE THE WDK ENGINE
console.log(`${B}H. TRON rail — 1 USDT → DENY INSIDE THE WDK POLICY ENGINE${X}`);
const before = tronCalls.n;
let hErr;
try { await usdtPay(1); } catch (err) { hErr = err; }
expect('WDK engine raised PolicyViolationError (OP DENY rule, fail-closed backbone)', hErr instanceof PolicyViolationError, String(hErr));
expect('base transfer was never invoked (nothing to broadcast)', tronCalls.n === before);
console.log(`   ${D}${String(hErr?.message ?? '').slice(0, 140)}${X}\n`);

// ── Decision proof ─────────────────────────────────────────────────────────
console.log(`${B}Decision log (append-only, one line per verdict)${X}`);
for (const line of readFileSync(join(out, 'decisions.jsonl'), 'utf8').trim().split('\n')) {
  const e = JSON.parse(line);
  console.log(`   ${e.decision === 'allow' ? G + 'ALLOW' : R + 'DENY '}${X} ${(e.kind ?? '').padEnd(12)} ${e.reason.slice(0, 100)}`);
}
console.log(`${B}Shared cross-rail ledger${X} (${ledgerPath.replace(here + '/', 'demo/')})`);
for (const line of readFileSync(ledgerPath, 'utf8').trim().split('\n')) {
  const e = JSON.parse(line);
  console.log(`   ${D}${e.rail.padEnd(20)} ${e.amountRaw.padStart(8)} ${e.asset}${X}`);
}

console.log(`\n${failures === 0 ? G + B + 'DEMO GREEN' : R + B + 'DEMO RED'}${X} — one signed mandate, one 24h budget: USDC-on-Base (x402) + Lightning (L402) + USDT-on-TRON (WDK). Over-budget attempts denied at the key, at the hook, and inside Tether's own policy engine.`);
process.exit(failures === 0 ? 0 : 1);
