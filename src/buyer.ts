// Buyer-side enforcement on the x402 payment path. Before an agent signs the
// EIP-3009 authorization that IS an x402 payment, evaluate its signed,
// revocable delegation against the proposed transfer, fail-closed. A denied
// payment is never signed; an unsigned authorization cannot settle — this is
// pre-execution enforcement in the strict sense.
//
// Counters: both the same-asset velocity counter and the cross-rail budget
// total come from the shared CrossRailLedger (one file, all rails). Explicit
// overrides win, so stateless conformance tests can drive the evaluator
// without a filesystem ledger.

import { verifyCredential, enforceMandate } from '@observer-protocol/policy-engine';
import type {
  CrossRailLedger,
  PolicyContext,
  ResolvedTransfer,
  TokenDefConfig,
  Verdict,
  VerifierConfig,
} from '@observer-protocol/policy-engine';
import { DEFAULT_EVM_TOKENS, formatBudgetUnits } from '@observer-protocol/policy-engine';
import { X402_EVM_TOKENS, type DecodedX402 } from './x402.js';

export interface X402AuthInput {
  decoded: Extract<DecodedX402, { kind: 'eip3009-transfer' }>;
  /** The wrapped account's address. The authorization's `from` must match it:
   * signing a transfer out of someone else's wallet is never ours to allow. */
  walletAddress: string;
  /** Evaluation time (ms). Defaults to now. */
  nowMs?: number;
  /** Shared cross-rail ledger; source of both counters when set. */
  ledger?: CrossRailLedger;
  /** Explicit same-asset rolling total (raw units) — overrides the ledger. */
  dailyTotalRaw?: bigint;
  /** Explicit cross-rail total (CROSS_RAIL_SCALE units) — overrides the ledger. */
  crossRailTotal?: { total: bigint; currency: string };
}

function tokenFor(config: VerifierConfig, contract: string): TokenDefConfig | undefined {
  return config.evmTokens?.[contract] ?? X402_EVM_TOKENS[contract] ?? DEFAULT_EVM_TOKENS[contract];
}

/** Build the single asset/amount/counterparty view the mandate enforces
 * against, from the decoded EIP-3009 authorization. An unrecognized token
 * contract is unenforceable: the mandate's amount/counterparty constraints
 * cannot be scaled against an asset we cannot identify, so any binding
 * constraint denies. */
export function resolvedFromX402(
  config: VerifierConfig,
  d: Extract<DecodedX402, { kind: 'eip3009-transfer' }>,
): ResolvedTransfer {
  const token = tokenFor(config, d.verifyingContract);
  if (!token) {
    return {
      kind: 'evm-token',
      recipient: d.to,
      recipientKind: 'wallet',
      notes: [],
      unenforceable: `EIP-3009 authorization on unrecognized token contract ${d.verifyingContract} — asset cannot be identified, so amounts cannot be scaled against the mandate`,
    };
  }
  return {
    kind: 'evm-token',
    assetSymbol: token.symbol,
    amount: d.value,
    decimals: token.decimals,
    recipient: d.to,
    recipientKind: 'wallet',
    notes: [`x402 exact/EVM payment: ${token.symbol} on eip155:${d.chainId}, authorization valid [${d.validAfter}, ${d.validBefore}]`],
  };
}

/**
 * Authorize (or deny) a proposed x402 payment against the agent's delegation.
 * Runs the full credential verification (pinned issuer, eddsa-jcs-2022 proof,
 * revocation, signer-boundary) then the mandate enforcement (per-payment
 * ceiling, counterparty = the SIGNED payTo, velocity, cross-rail budget).
 * Fail-closed on any miss.
 */
export async function authorizeX402Payment(config: VerifierConfig, input: X402AuthInput): Promise<Verdict> {
  const d = input.decoded;
  const nowMs = input.nowMs ?? Date.now();
  const notes: string[] = [];

  if (d.from.toLowerCase() !== input.walletAddress.toLowerCase()) {
    return {
      allow: false,
      reason: `[from] authorization.from ${d.from} is not the wrapped account ${input.walletAddress} — this signer never authorizes transfers out of another wallet`,
      notes,
    };
  }
  const nowSec = BigInt(Math.floor(nowMs / 1000));
  if (d.validBefore <= nowSec) {
    return {
      allow: false,
      reason: `[window] authorization validBefore ${d.validBefore} is already in the past — a dead authorization is never signed`,
      notes,
    };
  }

  const credVerdict = await verifyCredential(config, nowMs);
  if (!credVerdict.allow || !credVerdict.cred) return credVerdict;
  const cred = credVerdict.cred;
  const resolved = resolvedFromX402(config, d);

  const chainId = `eip155:${d.chainId}`;
  let ctx: PolicyContext = {
    chain_id: chainId,
    wallet_id: input.walletAddress,
    api_key_id: 'x402',
    transaction: { to: d.to },
    timestamp: new Date(nowMs).toISOString(),
  };

  // Same-asset velocity counter (explicit override > ledger > absent).
  const tm = cred.credentialSubject.tradingMandate;
  let dailyTotalRaw = input.dailyTotalRaw;
  if (dailyTotalRaw === undefined && input.ledger && resolved.assetSymbol) {
    dailyTotalRaw = input.ledger.sumWindowRaw(resolved.assetSymbol, nowMs);
  }
  if (dailyTotalRaw !== undefined) {
    ctx = { ...ctx, spending: { daily_total: dailyTotalRaw.toString(), date: ctx.timestamp.slice(0, 10) } };
  }

  // Cross-rail budget total, converted at the mandate's principal-attested
  // rates. A ledger sum that cannot be established (unpriceable in-window
  // spend) denies here rather than silently under-counting.
  const crb = tm?.crossRailBudget;
  if (input.crossRailTotal) {
    ctx = { ...ctx, cross_rail: { total: input.crossRailTotal.total.toString(), currency: input.crossRailTotal.currency } };
  } else if (crb && input.ledger) {
    if (crb.rates && typeof crb.rates === 'object') {
      const sum = input.ledger.sumWindowConverted(crb.rates, nowMs);
      if (!sum.ok) {
        return { allow: false, reason: `[cross-rail] ${sum.reason}`, notes: [...credVerdict.notes] };
      }
      ctx = { ...ctx, cross_rail: { total: sum.total.toString(), currency: crb.currency } };
      notes.push(`cross-rail ledger total before this payment: ${formatBudgetUnits(sum.total)} ${crb.currency}`);
    }
    // malformed crb.rates: fall through with no counter — the evaluator's own
    // shape check denies with the canonical reason.
  }

  const verdict = enforceMandate(ctx, cred, config, resolved);
  return {
    allow: verdict.allow,
    reason: verdict.reason,
    notes: [...credVerdict.notes, ...notes, ...verdict.notes],
    cred,
  };
}
