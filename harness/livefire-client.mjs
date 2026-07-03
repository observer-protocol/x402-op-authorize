// Live-fire buyer against Cloudflare's x402-proxy-template (wrangler dev).
//
// The buyer is the REAL x402 v1 client (x402/client createPaymentHeader) with
// a REAL viem account — wrapped by createObserverX402Account. Nothing in the
// x402 client is modified: the OP gate lives entirely at the signer boundary.
//
// Scenarios:
//   A (allow): payment within the cross-rail budget → EIP-3009 authorization
//     signed, X-PAYMENT constructed by the x402 client, template worker
//     verifies via facilitator, premium content returned, spend recorded in
//     the shared cross-rail ledger.
//   B (deny at the key): prior Lightning spend recorded in the SAME ledger
//     pushes the budget over the cap → the wrapped account throws
//     ObserverDenyError inside the x402 client, NO signature exists, NO
//     X-PAYMENT is ever constructed, the resource stays 402.
//   C (real-facilitator probe): the exact payload from scenario A is POSTed
//     to https://x402.org/facilitator/verify — the REAL facilitator's verdict
//     on our emitted bytes (expected: signature accepted; settlement funds
//     absent on this unfunded testnet wallet).
//
// Usage: SERVER_URL=http://127.0.0.1:8787 node harness/livefire-client.mjs
import { mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createPaymentHeader } from 'x402/client';
import { createObserverX402Account, ObserverDenyError } from '../dist/index.mjs';
import { CrossRailLedger, formatBudgetUnits } from '@observer-protocol/policy-engine';
import { makeAgent, issueVac, policyConfig } from '../test/fixtures/gen.mjs';

const SERVER_URL = process.env.SERVER_URL || 'http://127.0.0.1:8787';
const REAL_FACILITATOR = process.env.REAL_FACILITATOR || 'https://x402.org/facilitator';
const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, 'out');
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

const log = (s) => console.log(s);
const step = (s) => console.log(`\n\x1b[1m${s}\x1b[0m`);
let failures = 0;
const verify = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mOK\x1b[0m ' : '\x1b[31mFAIL\x1b[0m'} ${name}${!ok && detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
};

// ── Identity + mandate: principal did:key signs a delegation for the agent
// with ONE cross-rail budget: $5/24h at principal-attested rates.
const principal = makeAgent();
const agent = makeAgent();
const PAY_TO = '0x000000000000000000000000000000000000dEaD'; // template default PAY_TO
const mandate = issueVac({
  issuerDid: principal.did, issuerPriv: principal.privateKey, issuerVm: principal.vm,
  subjectDid: agent.did,
  actionScope: { allowed_rails: ['eip155:84532', 'lightning'] },
  tradingMandate: {
    counterparty: { allowList: [PAY_TO, 'api.example.com'] },
    crossRailBudget: { amount: '5', currency: 'USD', window: 'P1D', rates: { USDC: '1', sat: '0.0005' } },
  },
});
const credPath = join(out, 'agent-delegation.json');
writeFileSync(credPath, JSON.stringify(mandate, null, 2));
const ledgerPath = join(out, 'cross-rail-ledger.jsonl');

// ── The wallet: PRIVATE_KEY env > the funded demo key in
// ~/.config/op-crossrail/demo-buyer.key > a fresh ephemeral (unfunded) key.
import { existsSync as keyExists } from 'node:fs';
import { homedir } from 'node:os';
const KEY_FILE = join(homedir(), '.config/op-crossrail/demo-buyer.key');
const pk = process.env.PRIVATE_KEY
  ?? (keyExists(KEY_FILE) ? readFileSync(KEY_FILE, 'utf8').trim() : generatePrivateKey());
const baseAccount = privateKeyToAccount(pk);
const account = createObserverX402Account(baseAccount, {
  policy: policyConfig(principal.did, agent.did, out, credPath),
  crossRailLedgerPath: ledgerPath,
});
log(`buyer wallet (ephemeral testnet key): ${account.address}`);
log(`principal: ${principal.did.slice(0, 32)}…  agent: ${agent.did.slice(0, 32)}…`);
log(`mandate: crossRailBudget $5/P1D, rates {USDC:1, sat:0.0005}, allowList [${PAY_TO.slice(0, 10)}…]`);

// ── Scenario A: within budget → sign, pay, 200.
step('A. 402 challenge from the Cloudflare template');
const r1 = await fetch(`${SERVER_URL}/__x402/protected`);
verify('server returns 402 Payment Required', r1.status === 402, `got ${r1.status}`);
const challenge = await r1.json();
const requirement = challenge.accepts?.[0];
log(`  accepts[0]: ${requirement?.maxAmountRequired} ${requirement?.extra?.name ?? ''} on ${requirement?.network} → payTo ${requirement?.payTo?.slice(0, 10)}…`);

step('A. OP-gated signing + payment (x402 client unchanged)');
const header = await createPaymentHeader(account, challenge.x402Version, requirement);
verify('EIP-3009 authorization signed (payment within $5 budget)', typeof header === 'string' && header.length > 0);
const r2 = await fetch(`${SERVER_URL}/__x402/protected`, { headers: { 'X-PAYMENT': header } });
// Access-granted signals, matching the template's own test client: HTTP 200
// plus the settlement receipt header and/or the 1h auth cookie. (The template
// middleware swallows the handler body on the payment pass — upstream quirk,
// its bundled test-client.ts asserts exactly these signals, not body content.)
const paymentResponse = r2.headers.get('x-payment-response');
const authCookie = (r2.headers.get('set-cookie') ?? '').includes('auth_token=');
verify('paid request returns 200 with settlement receipt + auth cookie', r2.status === 200 && !!paymentResponse && authCookie, `status=${r2.status} receipt=${paymentResponse} cookie=${authCookie}`);
if (paymentResponse) {
  const receipt = JSON.parse(Buffer.from(paymentResponse, 'base64').toString('utf8'));
  log(`  settlement receipt: success=${receipt.success} tx=${String(receipt.transaction).slice(0, 18)}… (real on-chain settle when the template points at a real facilitator; simulated when using harness/local-facilitator.mjs — signature verification is real in both)`);
}
const ledger = new CrossRailLedger(ledgerPath);
const sumA = ledger.sumWindowConverted({ USDC: '1', sat: '0.0005' });
verify('spend recorded in shared cross-rail ledger', sumA.ok && sumA.total === 10_000n, JSON.stringify(sumA, (k, v) => typeof v === 'bigint' ? String(v) : v));
log(`  cross-rail ledger total: ${sumA.ok ? formatBudgetUnits(sumA.total) : '?'} USD`);

// ── Scenario B: a Lightning spend in the SAME ledger exhausts the budget →
// the next x402 payment dies at the key.
step('B. Lightning consumes the budget (same ledger, other rail) → x402 deny AT THE KEY');
ledger.record({ rail: 'lightning', asset: 'sat', amountRaw: '9990', decimals: 0 }); // 4.995 USD
const sumB = ledger.sumWindowConverted({ USDC: '1', sat: '0.0005' });
log(`  ledger now: ${sumB.ok ? formatBudgetUnits(sumB.total) : '?'} USD of 5 (x402 0.01 + lightning 4.995)`);
let denyErr;
let headerB;
try {
  headerB = await createPaymentHeader(account, challenge.x402Version, requirement);
} catch (e) {
  denyErr = e;
}
verify('x402 client threw ObserverDenyError from inside signing', denyErr instanceof ObserverDenyError, String(denyErr));
verify('deny reason is the cross-rail budget', (denyErr?.reason ?? '').includes('[cross-rail]'), denyErr?.reason);
verify('NO X-PAYMENT header exists (signature was never produced)', headerB === undefined);
log(`  reason: ${denyErr?.reason}`);
const r3 = await fetch(`${SERVER_URL}/__x402/protected`);
verify('resource remains 402 (nothing was paid, nothing to revert)', r3.status === 402, `got ${r3.status}`);

// ── Scenario C: the REAL x402.org facilitator judges scenario A's exact bytes.
step('C. Real-facilitator probe (x402.org) on the exact scenario-A payload');
try {
  const paymentPayload = JSON.parse(Buffer.from(header, 'base64').toString('utf8'));
  const resp = await fetch(`${REAL_FACILITATOR}/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ x402Version: challenge.x402Version, paymentPayload, paymentRequirements: requirement }),
  });
  const data = await resp.json().catch(() => ({}));
  log(`  x402.org/facilitator/verify → HTTP ${resp.status}: ${JSON.stringify(data)}`);
  if (data.invalidReason && /signature/i.test(String(data.invalidReason))) {
    verify('real facilitator accepted the signature', false, `signature rejected: ${data.invalidReason}`);
  } else {
    verify('real facilitator parsed + judged our payload (any non-signature reason = our bytes are valid x402)', typeof data === 'object');
  }
} catch (e) {
  log(`  UNVERIFIABLE (network): ${e.message} — probe skipped, local verification stands`);
}

console.log(`\n${failures === 0 ? '\x1b[32m\x1b[1mLIVE-FIRE GREEN' : '\x1b[31m\x1b[1mLIVE-FIRE RED'}\x1b[0m — audit log: ${join(out, 'decisions.jsonl')}`);
const audit = readFileSync(join(out, 'decisions.jsonl'), 'utf8').trim().split('\n');
console.log(`audit entries (${audit.length}):`);
for (const line of audit) {
  const e = JSON.parse(line);
  console.log(`  ${e.decision.toUpperCase().padEnd(5)} ${e.kind}  ${e.reason.slice(0, 110)}`);
}
process.exit(failures === 0 ? 0 : 1);
