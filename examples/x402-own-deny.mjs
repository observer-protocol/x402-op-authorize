#!/usr/bin/env node
/**
 * x402-op-authorize — reproduce the at-the-key DENY on your own machine.
 *
 * The hands-on companion to the recorded demo at observerprotocol.org/enforcement.
 * Runs entirely in-process: no OP backend, no network, no x402 server. It wraps a
 * viem account with the Observer Protocol x402 authorizer and makes two EIP-3009
 * TransferWithAuthorization signing calls against a signed $5-per-payment mandate:
 *
 *   1. an in-cap payment  -> the EIP-3009 signature is produced (ALLOW)
 *   2. an over-cap payment -> ObserverDenyError is thrown BEFORE any signature
 *      exists (DENY AT THE KEY)
 *
 * The deny lands at the signer boundary: no signature is ever created, so nothing
 * can settle. This is the same grade the recorded demo shows, reproduced by your
 * own agent's key.
 *
 *   npm install && npm run build   # once, in this repo
 *   node examples/x402-own-deny.mjs
 */
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { createObserverX402Account, ObserverDenyError } from '../dist/index.mjs';
import { makeAgent, issueVac, policyConfig } from '../test/fixtures/gen.mjs';

const USDC_SEPOLIA = '0x036CbD53842c5426634e7929541eC2318f3dCF7e'; // USDC on Base Sepolia
const PAY_TO = '0x000000000000000000000000000000000000dEaD';
const CAP_USDC = 5; // per-payment ceiling in the signed mandate
const usdcUnits = (n) => String(BigInt(Math.round(n * 1e6))); // USDC has 6 decimals

const work = mkdtempSync(join(tmpdir(), 'x402-own-deny-'));
const principal = makeAgent(); // the principal who signs the mandate
const agent = makeAgent();     // the agent the mandate authorizes

// One signed OP delegation: this agent may spend up to $5 per x402 payment to PAY_TO.
const mandate = issueVac({
  issuerDid: principal.did, issuerPriv: principal.privateKey, issuerVm: principal.vm,
  subjectDid: agent.did,
  actionScope: { allowed_rails: ['eip155:84532'] },
  tradingMandate: { unit: 'USDC', maxNotionalPerOrder: CAP_USDC, counterparty: { allowList: [PAY_TO] } },
});
const credPath = join(work, 'agent-delegation.json');
writeFileSync(credPath, JSON.stringify(mandate, null, 2));

// Wrap a real viem account. The wrapper IS the signer, so "deny" means the
// signature never exists. (Bring your own key via PRIVATE_KEY, or a throwaway
// one is generated — no funds are needed; the deny fires before signing.)
const buyer = privateKeyToAccount(process.env.PRIVATE_KEY ?? generatePrivateKey());
const account = createObserverX402Account(buyer, {
  policy: policyConfig(principal.did, agent.did, work, credPath),
  crossRailLedgerPath: join(work, 'cross-rail-ledger.jsonl'),
});

// Build an x402 exact/EVM authorization exactly as the x402 client's
// signAuthorization does — an EIP-3009 TransferWithAuthorization.
function eip3009({ usdc }) {
  const nowSec = Math.floor(Date.now() / 1000);
  return {
    domain: { name: 'USDC', version: '2', chainId: 84532, verifyingContract: USDC_SEPOLIA },
    primaryType: 'TransferWithAuthorization',
    types: {
      TransferWithAuthorization: [
        { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
        { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
      ],
    },
    message: {
      from: account.address, to: PAY_TO, value: usdcUnits(usdc),
      validAfter: '0', validBefore: String(nowSec + 600), nonce: '0x' + 'ab'.repeat(32),
    },
  };
}

console.log(`\nMandate: this agent may spend up to $${CAP_USDC}.00 per x402 payment to ${PAY_TO}.`);
console.log(`Signer:  ${account.address}  (the OP wrapper IS the signer)\n`);

// 1. In-cap payment -> signature is produced.
const okSig = await account.signTypedData(eip3009({ usdc: 1 }));
console.log(`$1.00 payment  ->  ALLOWED. EIP-3009 signature produced: ${okSig.slice(0, 24)}...`);

// 2. Over-cap payment -> deny at the key, no signature ever exists.
try {
  await account.signTypedData(eip3009({ usdc: 6 }));
  console.log('$6.00 payment  ->  UNEXPECTED: a signature was produced. This should not happen.');
  process.exit(1);
} catch (err) {
  if (!(err instanceof ObserverDenyError)) { console.error('Unexpected error:', err); process.exit(1); }
  console.log(`$6.00 payment  ->  DENIED AT THE KEY. No EIP-3009 signature exists; nothing can settle.`);
  console.log(`                  reason: ${err.reason ?? err.message}`);
  console.log(`\nSame grade as observerprotocol.org/enforcement, at the signer boundary, on your own machine.\n`);
}
