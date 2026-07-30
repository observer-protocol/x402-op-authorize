// Conformance harness for @observer-protocol/x402-op-authorize.
// Every rule is exercised on BOTH sides (allow and deny) — path-green is not
// component-green. Summary line format is parsed by the shared parity harness:
//   "N/M conformance cases passed"
import { hashTypedData } from 'viem';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createObserverX402Account,
  authorizeX402Payment,
  decodeX402TypedData,
  ObserverDenyError,
} from '../dist/index.mjs';
import {
  CrossRailLedger,
  convertToBudgetUnits,
  parseConfig,
} from '@observer-protocol/policy-engine';
import { writeFixtures, policyConfig } from './fixtures/gen.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const work = mkdtempSync(join(tmpdir(), 'x402-op-'));
const fx = writeFixtures(join(work, 'fixtures'));

const USDC_SEPOLIA = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
const WALLET = '0x857b06519E91e3A54538791bDbb0E22373e36b66';
const NOW = Date.now();
const nowSec = Math.floor(NOW / 1000);

/** Build x402 exact/EVM typed data the way x402/client's signAuthorization does. */
function typedData({ value, to = fx.payTo, from = WALLET, chainId = 84532, contract = USDC_SEPOLIA, validBefore = nowSec + 600, primaryType = 'TransferWithAuthorization' } = {}) {
  return {
    domain: { name: 'USDC', version: '2', chainId, verifyingContract: contract },
    primaryType,
    types: {
      TransferWithAuthorization: [
        { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
        { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
      ],
    },
    message: { from, to, value: String(value), validAfter: '0', validBefore: String(validBefore), nonce: '0x' + 'ab'.repeat(32) },
  };
}

const cfgFor = (credName) => parseConfig(policyConfig(fx.principal.did, fx.agent.did, work, fx.paths[credName]));
const decoded = (over) => {
  const d = decodeX402TypedData(typedData(over));
  if (d.kind !== 'eip3009-transfer') throw new Error('fixture typed data must decode: ' + d.reason);
  return d;
};

let pass = 0, fail = 0;
const results = [];
function check(name, ok, detail = '') {
  if (ok) { pass++; results.push(`  PASS  ${name}`); }
  else { fail++; results.push(`  FAIL  ${name}${detail ? ' — ' + detail : ''}`); }
}
async function expectVerdict(name, promise, wantAllow, wantReasonPart) {
  const v = await promise;
  const okAllow = v.allow === wantAllow;
  const okReason = wantReasonPart ? (v.reason ?? '').includes(wantReasonPart) : true;
  check(name, okAllow && okReason, `allow=${v.allow} reason=${v.reason}`);
  return v;
}

// ---------- decoder ----------
{
  const d = decodeX402TypedData(typedData({ value: 1_500_000 }));
  check('decode: exact/EVM authorization → all signed fields extracted',
    d.kind === 'eip3009-transfer' && d.value === 1500000n && d.to === fx.payTo && d.chainId === 84532 && d.verifyingContract === USDC_SEPOLIA.toLowerCase());
  check('decode: Permit2 witness → recognized payment-bearing, not decoded',
    decodeX402TypedData(typedData({ primaryType: 'PermitWitnessTransferFrom' })).kind === 'permit2-witness');
  check('decode: ReceiveWithAuthorization → recognized payment-bearing',
    decodeX402TypedData(typedData({ primaryType: 'ReceiveWithAuthorization' })).kind === 'eip3009-receive');
  check('decode: CancelAuthorization → benign',
    decodeX402TypedData(typedData({ primaryType: 'CancelAuthorization' })).kind === 'cancel-authorization');

  check('decode: missing value → unknown (undecodable fails closed downstream)',
    decodeX402TypedData({ primaryType: 'TransferWithAuthorization', domain: { chainId: 84532, verifyingContract: USDC_SEPOLIA }, message: { from: WALLET, to: fx.payTo } }).kind === 'unknown');
}

// ---------- conversion math ----------
{
  check('convert: 1 USDC (6dp) at rate 1 → 1.000000 USD', convertToBudgetUnits(1_000_000n, 6, '1') === 1_000_000n);
  check('convert: 1000 sat (0dp) at rate 0.0005 → 0.5 USD', convertToBudgetUnits(1000n, 0, '0.0005') === 500_000n);
  check('convert: rounds UP (1 sat at 0.0005 → 0.000500 USD exact; 1 sat at 0.00000049 → ceil)',
    convertToBudgetUnits(1n, 0, '0.0005') === 500n && convertToBudgetUnits(1n, 0, '0.00000049') === 1n);
}

// ---------- credential pipeline (deny side) ----------
await expectVerdict('cred: expired → deny [validity]',
  authorizeX402Payment(cfgFor('cred-expired'), { decoded: decoded({ value: 1_000_000 }), walletAddress: WALLET }), false, 'validity');
await expectVerdict('cred: tampered budget → deny [proof]',
  authorizeX402Payment(cfgFor('cred-tampered'), { decoded: decoded({ value: 1_000_000 }), walletAddress: WALLET }), false, '[proof]');
// Even a deployment misconfigured to TRUST the agent's own DID as issuer is
// caught: the signer-boundary check denies a mandate signed by the agent key.
await expectVerdict('cred: agent-self-issued → deny [signer-boundary]',
  authorizeX402Payment(parseConfig(policyConfig(fx.agent.did, fx.agent.did, work, fx.paths['cred-agent-self-issued'])),
    { decoded: decoded({ value: 1_000_000 }), walletAddress: WALLET }), false, 'signer-boundary');
await expectVerdict('cred: unknown tradingMandate rule → deny [unknown-rule]',
  authorizeX402Payment(cfgFor('cred-unknown-tm-rule'), { decoded: decoded({ value: 1_000_000 }), walletAddress: WALLET }), false, 'unknown-rule');

// ---------- x402 payment gate ----------
await expectVerdict('x402: within ceiling + allowlisted payTo → ALLOW',
  authorizeX402Payment(cfgFor('cred-x402-valid'), { decoded: decoded({ value: 4_000_000 }), walletAddress: WALLET, dailyTotalRaw: 0n }), true);
await expectVerdict('x402: over maxNotionalPerOrder → deny [notional]',
  authorizeX402Payment(cfgFor('cred-x402-valid'), { decoded: decoded({ value: 6_000_000 }), walletAddress: WALLET, dailyTotalRaw: 0n }), false, '[notional]');
// v2.4 + Sovereign spending_limits.per_rail shape (Sovereign→x402 path).
await expectVerdict('x402: v2.4 spending_limits in-cap → ALLOW',
  authorizeX402Payment(cfgFor('cred-x402-v24-spending'), { decoded: decoded({ value: 4_000_000, to: fx.payTo }), walletAddress: WALLET, dailyTotalRaw: 0n }), true);
await expectVerdict('x402: v2.4 spending_limits over-cap → deny [spending-limits]',
  authorizeX402Payment(cfgFor('cred-x402-v24-spending'), { decoded: decoded({ value: 6_000_000, to: fx.payTo }), walletAddress: WALLET, dailyTotalRaw: 0n }), false, '[spending-limits]');
await expectVerdict('x402: payTo not on allowList → deny [counterparty]',
  authorizeX402Payment(cfgFor('cred-x402-valid'), { decoded: decoded({ value: 1_000_000, to: '0x1111111111111111111111111111111111111111' }), walletAddress: WALLET, dailyTotalRaw: 0n }), false, '[counterparty]');
await expectVerdict('x402: velocity under dailyVolumeCap → ALLOW',
  authorizeX402Payment(cfgFor('cred-x402-valid'), { decoded: decoded({ value: 2_000_000 }), walletAddress: WALLET, dailyTotalRaw: 5_000_000n }), true);
await expectVerdict('x402: velocity over dailyVolumeCap → deny [velocity]',
  authorizeX402Payment(cfgFor('cred-x402-valid'), { decoded: decoded({ value: 4_000_000 }), walletAddress: WALLET, dailyTotalRaw: 5_000_000n }), false, '[velocity]');
await expectVerdict('x402: authorization.from is another wallet → deny [from]',
  authorizeX402Payment(cfgFor('cred-x402-valid'), { decoded: decoded({ value: 1_000_000, from: '0x2222222222222222222222222222222222222222' }), walletAddress: WALLET, dailyTotalRaw: 0n }), false, '[from]');
await expectVerdict('x402: validBefore already past → deny [window]',
  authorizeX402Payment(cfgFor('cred-x402-valid'), { decoded: decoded({ value: 1_000_000, validBefore: nowSec - 10 }), walletAddress: WALLET, dailyTotalRaw: 0n }), false, '[window]');
await expectVerdict('x402: unmapped chain → deny [rails]',
  authorizeX402Payment(cfgFor('cred-x402-valid'), { decoded: decoded({ value: 1_000_000, chainId: 999999 }), walletAddress: WALLET, dailyTotalRaw: 0n }), false, '[rails]');
await expectVerdict('x402: unknown token contract under amount cap → deny [unenforceable]',
  authorizeX402Payment(cfgFor('cred-x402-valid'), { decoded: decoded({ value: 1_000_000, contract: '0x3333333333333333333333333333333333333333' }), walletAddress: WALLET, dailyTotalRaw: 0n }), false, '[unenforceable]');

// ---------- cross-rail budget ----------
{
  const ledger = new CrossRailLedger(join(work, 'ledger.jsonl'));
  // A Lightning spend recorded by the OTHER engine: 6000 sats = 3.00 USD at the mandate rate.
  ledger.record({ rail: 'lightning', asset: 'sat', amountRaw: '6000', decimals: 0 });

  await expectVerdict('cross-rail: x402 1.5 USDC after 3 USD Lightning spend (4.5/5) → ALLOW',
    authorizeX402Payment(cfgFor('cred-cross-rail'), { decoded: decoded({ value: 1_500_000 }), walletAddress: WALLET, ledger }), true);
  await expectVerdict('cross-rail: x402 2.5 USDC after 3 USD Lightning spend (5.5/5) → deny [cross-rail]',
    authorizeX402Payment(cfgFor('cred-cross-rail'), { decoded: decoded({ value: 2_500_000 }), walletAddress: WALLET, ledger }), false, '[cross-rail]');
  await expectVerdict('cross-rail: budget mandate with NO counter (no ledger) → deny [cross-rail]',
    authorizeX402Payment(cfgFor('cred-cross-rail'), { decoded: decoded({ value: 1_000_000 }), walletAddress: WALLET }), false, 'no cross-rail counter');
  await expectVerdict('cross-rail: transfer asset has no principal-attested rate → deny [cross-rail]',
    authorizeX402Payment(cfgFor('cred-cross-rail-norate'), { decoded: decoded({ value: 1_000_000 }), walletAddress: WALLET, ledger }), false, 'no principal-attested rate');
  await expectVerdict('cross-rail: unsupported window P2D → deny [cross-rail]',
    authorizeX402Payment(cfgFor('cred-cross-rail-badwindow'), { decoded: decoded({ value: 1_000_000 }), walletAddress: WALLET, crossRailTotal: { total: 0n, currency: 'USD' } }), false, 'window');
  await expectVerdict('cross-rail: counter currency mismatch → deny [cross-rail]',
    authorizeX402Payment(cfgFor('cred-cross-rail'), { decoded: decoded({ value: 1_000_000 }), walletAddress: WALLET, crossRailTotal: { total: 0n, currency: 'EUR' } }), false, 'not comparable');

  // Unpriceable in-window spend poisons the total → deny, never under-count.
  const ledger2 = new CrossRailLedger(join(work, 'ledger2.jsonl'));
  ledger2.record({ rail: 'tron:mainnet', asset: 'USDT', amountRaw: '1000000', decimals: 6 });
  await expectVerdict('cross-rail: in-window spend with no rate in mandate → deny (total unestablishable)',
    authorizeX402Payment(cfgFor('cred-cross-rail'), { decoded: decoded({ value: 1_000_000 }), walletAddress: WALLET, ledger: ledger2 }), false, 'cross-rail total cannot be established');

  // Reserve/release lifecycle.
  const ledger3 = new CrossRailLedger(join(work, 'ledger3.jsonl'));
  const rid = ledger3.reserve({ rail: 'lightning', asset: 'sat', amountRaw: '4000', decimals: 0 });
  const withReserve = ledger3.sumWindowConverted({ sat: '0.0005' });
  ledger3.release(rid);
  const afterRelease = ledger3.sumWindowConverted({ sat: '0.0005' });
  check('ledger: reservation counts toward the window and release restores headroom',
    withReserve.ok && withReserve.total === 2_000_000n && afterRelease.ok && afterRelease.total === 0n,
    JSON.stringify({ withReserve, afterRelease }, (k, v) => typeof v === 'bigint' ? String(v) : v));
  const rid2 = ledger3.reserve({ rail: 'lightning', asset: 'sat', amountRaw: '4000', decimals: 0 });
  ledger3.commit(rid2);
  const afterCommit = ledger3.sumWindowConverted({ sat: '0.0005' });
  check('ledger: commit converts a reservation to a permanent entry',
    afterCommit.ok && afterCommit.total === 2_000_000n);
}

// ---------- account wrapper (the signer boundary itself) ----------
{
  const calls = [];
  const baseAccount = {
    address: WALLET,
    type: 'local',
    source: 'test',
    async signMessage() { calls.push('message'); return '0x01'; },
    async signTransaction() { calls.push('tx'); return '0x02'; },
    async signTypedData() { calls.push('typed'); return '0x03'; },
    async sign() { calls.push('raw'); return '0x04'; },
  };
  const mk = (credName, extra = {}) => createObserverX402Account(baseAccount, {
    policy: policyConfig(fx.principal.did, fx.agent.did, work, fx.paths[credName]),
    crossRailLedgerPath: join(work, 'account-ledger.jsonl'),
    ...extra,
  });

  // ─── X402-D5 PINNING ──────────────────────────────────────────────────────
  //
  // THESE ASSERT A DEFECT, DELIBERATELY. X402-D5 is open in the registry: the
  // cancel-authorization branch signs on the DEFAULT config with no mandate evaluation
  // (src/account.ts:68-71). It is an ALLOW returned where the verdict should be evaluated, not a
  // reachability failure, so nothing here is a bypass.
  //
  // Pinned before anything moves it, so that when the evaluation lands these assertions FAIL and
  // must be rewritten deliberately rather than a behaviour change slipping past a green suite.
  //
  // INTERIM IS ALLOW, AND THAT IS A DECISION RATHER THAN INERTIA. Deny-blanket breaks legitimate
  // housekeeping on every deployment on the default config, and would be the third arrival of a
  // blanket refusal already rejected twice. Allow-blanket is the shipped behaviour, recorded open,
  // and bounded by cancelling moving no money.
  //
  // THE FIX IS BLOCKED ON THE DECODER, NOT ON THE VOCABULARY. actionScope.cancellationAuthority is
  // served at observerprotocol.org/schemas/delegation/v2.5.json since 2026-07-30. But `agent`
  // allows, and `granting-party` (the schema DEFAULT) needs to know who granted the authorization
  // being cancelled, which requires the nonce. src/x402.ts:63-65 returns { kind, reason } and reads
  // no message fields, so the nonce is discarded and provenance is unanswerable.
  // ─── X402-D5: TWO FACTS ABOUT TWO DEPLOYMENTS ────────────────────────────
  //
  // The pin said "signed on the DEFAULT config". That is STILL TRUE for a library deployment and
  // NO LONGER TRUE for a service one, so it was split rather than deleted. Same shape as X402-P2
  // and X402-P3: collapsing two deployments to one verdict would be false about one of them.
  //
  // LIBRARY: no host to ask, so the behaviour is unchanged and the path stays open. Deny-blanket
  // was rejected — it breaks legitimate housekeeping on every library deployment and would be the
  // third arrival of a refusal already rejected twice.
  check('X402-D5 LIBRARY: with no resolver, the cancellation is still signed',
    await (async () => {
      const sig = await mk('cred-cross-rail').signTypedData(typedData({ primaryType: 'CancelAuthorization' }));
      return typeof sig === 'string' && sig.startsWith('0x');
    })());
  // But NO LONGER SILENTLY. "permitted" and "never assessed" were indistinguishable in the audit
  // log; now a reader can tell them apart, which is the difference between an open defect that is
  // visible and one that is not.
  check('X402-D5 LIBRARY: ...and the audit says it was signed WITHOUT a verdict',
    await (async () => {
      const logPath = join(work, 'cancel-audit.jsonl');
      const acct = createObserverX402Account(baseAccount, {
        policy: { ...policyConfig(fx.principal.did, fx.agent.did, work, fx.paths['cred-cross-rail']), auditLog: logPath },
      });
      await acct.signTypedData(typedData({ primaryType: 'CancelAuthorization' }));
      const written = readFileSync(logPath, 'utf8');
      return /WITHOUT A VERDICT/.test(written) && /no service to ask/.test(written);
    })());

  // SERVICE: a host that holds the mandate answers, and the path closes.
  check('X402-D5 SERVICE: a host DENY refuses the signature',
    await (async () => {
      const acct = mk('cred-cross-rail', {
        resolveCancelVerdict: async () => ({ allow: false, reason: 'Refused by the mandate: granted by approver human-1.' }),
      });
      try { await acct.signTypedData(typedData({ primaryType: 'CancelAuthorization' })); return false; }
      catch (e) { return e instanceof ObserverDenyError && /approver human-1/.test(e.message); }
    })());
  check('X402-D5 SERVICE: a host ALLOW signs it',
    await (async () => {
      const acct = mk('cred-cross-rail', {
        resolveCancelVerdict: async () => ({ allow: true, reason: 'Granted by the mandate.' }),
      });
      const sig = await acct.signTypedData(typedData({ primaryType: 'CancelAuthorization' }));
      return typeof sig === 'string' && sig.startsWith('0x');
    })());
  // The facts the host decides on must actually REACH it. A resolver called with undefined nonce
  // resolves provenance against nothing, which is the decoder defect one layer along.
  check('X402-D5 SERVICE: the decoded authorizer and nonce reach the host',
    await (async () => {
      let seen;
      const acct = mk('cred-cross-rail', {
        resolveCancelVerdict: async (f) => { seen = f; return { allow: true, reason: 'ok' }; },
      });
      await acct.signTypedData({
        domain: { name: 'USDC', version: '2', chainId: 84532, verifyingContract: USDC_SEPOLIA },
        primaryType: 'CancelAuthorization',
        types: { CancelAuthorization: [{ name: 'authorizer', type: 'address' }, { name: 'nonce', type: 'bytes32' }] },
        message: { authorizer: WALLET, nonce: '0x' + 'ef'.repeat(32) },
      });
      return seen?.authorizer === WALLET && seen?.nonce === '0x' + 'ef'.repeat(32);
    })());
  // WAS: 'the decoder discards the nonce, which is why the fix is blocked'. That pin has been
  // REWRITTEN DELIBERATELY rather than edited to match, because the blocker it recorded is gone:
  // the decoder now carries authorizer and nonce.
  //
  // ASSERTED AGAINST A viem-BUILT PAYLOAD, not a fixture of our own. The authority on what an
  // EIP-3009 CancelAuthorization message contains is the SDK that builds it, and a fixture we
  // wrote could only confirm our own reading. Same reason the transfer envelope was checked
  // against viem. This is a payload-classification path and the registry entry warns it is the
  // class that drifts when a counterparty SDK renames a typed-data suite.
  {
    const real = {
      domain: { name: 'USDC', version: '2', chainId: 84532, verifyingContract: USDC_SEPOLIA },
      primaryType: 'CancelAuthorization',
      types: { CancelAuthorization: [{ name: 'authorizer', type: 'address' }, { name: 'nonce', type: 'bytes32' }] },
      message: { authorizer: WALLET, nonce: '0x' + 'cd'.repeat(32) },
    };
    // viem hashing it is the evidence that this IS a well-formed CancelAuthorization, rather than
    // a shape we invented that our decoder happens to accept.
    check('decode: the payload viem accepts as CancelAuthorization is well-formed',
      typeof hashTypedData(real) === 'string');
    const d = decodeX402TypedData(real);
    check('decode: CancelAuthorization carries the authorizer', d.authorizer === WALLET);
    check('decode: CancelAuthorization carries the nonce', d.nonce === '0x' + 'cd'.repeat(32));
    // REPORTS, DOES NOT REPAIR. A missing field is reported absent rather than invented, because
    // an invented nonce would resolve provenance against the wrong payment.
    const bare = decodeX402TypedData({ ...real, message: {} });
    check('decode: a message without the fields reports them ABSENT rather than inventing them',
      bare.kind === 'cancel-authorization' && bare.authorizer === undefined && bare.nonce === undefined);
  }
  // BOTH OUTCOMES: a payment-bearing structure on the same path still denies, so the pin above is
  // about this branch and not about the guard having been disabled wholesale.
  check('X402-D5 PINNED: ...while a payment-bearing structure on the same path still DENIES',
    await (async () => {
      try { await mk('cred-cross-rail').signTypedData(typedData({ primaryType: 'ReceiveWithAuthorization' })); return false; }
      catch (e) { return e instanceof ObserverDenyError; }
    })());
  // ──────────────────────────────────────────────────────────────────────────

  const acct = mk('cred-cross-rail');
  const sig = await acct.signTypedData(typedData({ value: 1_000_000 }));
  check('account: allowed payment → base signature produced + spend recorded', sig === '0x03' && calls.includes('typed'));
  const ledgerNow = new CrossRailLedger(join(work, 'account-ledger.jsonl')).sumWindowConverted({ USDC: '1', sat: '0.0005' });
  check('account: ledger holds the 1 USDC spend', ledgerNow.ok && ledgerNow.total === 1_000_000n);

  calls.length = 0;
  let denied;
  try { await acct.signTypedData(typedData({ value: 4_500_000 })); } catch (e) { denied = e; }
  check('account: over-budget payment → ObserverDenyError, NO signature ever produced',
    denied instanceof ObserverDenyError && denied.reason.includes('[cross-rail]') && calls.length === 0);

  for (const [name, fn, tag] of [
    ['signTransaction', () => acct.signTransaction({}), '[tx]'],
    ['signMessage', () => acct.signMessage({ message: 'hi' }), '[signMessage]'],
    ['raw sign', () => acct.sign({ hash: '0x' + '00'.repeat(32) }), '[raw-sign]'],
  ]) {
    let err;
    try { await fn(); } catch (e) { err = e; }
    check(`account: ${name} denied by default (fail-closed)`, err instanceof ObserverDenyError && err.reason.includes(tag) && calls.length === 0);
  }

  let permit2Err;
  try { await acct.signTypedData(typedData({ primaryType: 'PermitWitnessTransferFrom' })); } catch (e) { permit2Err = e; }
  check('account: Permit2 typed data denied (payment-bearing, not decoded in v1)',
    permit2Err instanceof ObserverDenyError && calls.length === 0);

  let unknownErr;
  try { await acct.signTypedData({ primaryType: 'Mail', message: {} }); } catch (e) { unknownErr = e; }
  check('account: unknown typed data denied by default', unknownErr instanceof ObserverDenyError && calls.length === 0);

  const acctLoose = mk('cred-cross-rail', { allowNonPaymentTypedData: true });
  const looseSig = await acctLoose.signTypedData({ primaryType: 'Mail', message: {} });
  check('account: unknown typed data allowed UNGATED only with explicit knob', looseSig === '0x03');

  const cancelSig = await acct.signTypedData(typedData({ primaryType: 'CancelAuthorization' }));
  check('account: CancelAuthorization (benign, revokes an outstanding authorization) → allowed', cancelSig === '0x03');
}

console.log(results.join('\n'));
console.log(`\n${pass}/${pass + fail} conformance cases passed`);
rmSync(work, { recursive: true, force: true });
if (fail > 0) process.exit(1);
