import { parseConfig, appendAudit, CrossRailLedger, assertLedgerCoreSafe } from '@observer-protocol/policy-engine';
import type { AuditEntry, VerifierConfig } from '@observer-protocol/policy-engine';
import type { BaseAccount, Hex, ObserverX402AccountConfig, TypedDataLike } from './adapter-types.js';
import { ObserverDenyError } from './adapter-types.js';
import { decodeX402TypedData } from './x402.js';
import { authorizeX402Payment, resolvedFromX402 } from './buyer.js';

// The viem custom-account seam for x402 buyers. Wraps a base account and
// enforces the signed OP mandate at the signer boundary, fail-closed, before
// delegating to the base account's real signing. Pass the result anywhere an
// x402 client takes a viem account — x402's createPaymentHeader,
// wrapFetchWithPayment (x402-fetch / x402-axios), or Cloudflare's Agents SDK
// payment helpers — with zero changes to those libraries.
//
// Enforcement model (see SUPPORT-MATRIX):
//   signTypedData → the chokepoint. x402 exact/EVM payments are EIP-3009
//     TransferWithAuthorization typed data; the full shared mandate runs
//     (ceiling/counterparty/temporal/velocity/cross-rail) against the RAW
//     SIGNED FIELDS, and an allowed payment is recorded into the shared
//     cross-rail ledger before the signature is produced (the signature is
//     the spend commitment — settlement timing belongs to the facilitator).
//     Recognized payment suites this engine does not decode (Permit2, EIP-3009
//     receive) DENY. Unknown typed data DENIES by default.
//   signTransaction / signMessage / raw sign → DENIED by default (see
//     adapter-types.ts for the rationale on each knob).

export interface ObserverX402Account extends BaseAccount {
  /** The wrapped base account. */
  readonly base: BaseAccount;
}

interface X402AuditEntry extends AuditEntry {
  kind: 'x402-payment' | 'typed-data' | 'tx' | 'message' | 'raw-sign';
  asset?: string;
  amount?: string;
  recipient?: string;
  nonce?: string;
}

export function createObserverX402Account(base: BaseAccount, cfg: ObserverX402AccountConfig): ObserverX402Account {
  // Self-report the BUNDLED core: this adapter enforces with the policy-engine
  // frozen into its own dist at build time (not the version npm resolved). Warn
  // if that bundled core is below the ledger-safe floor; opt into a hard refuse
  // via cfg.refuseUnsafeCore. This is the only in-band signal that a shipped
  // build carries a fail-open/false-contend core — it travels with the bundle.
  assertLedgerCoreSafe({ mode: (cfg as { refuseUnsafeCore?: boolean }).refuseUnsafeCore ? 'refuse' : 'warn' });
  const config: VerifierConfig = parseConfig(cfg.policy);
  const ledger = cfg.crossRailLedgerPath ? new CrossRailLedger(cfg.crossRailLedgerPath) : undefined;
  const railLabel = cfg.railLabel ?? 'x402';

  const audit = (entry: Partial<X402AuditEntry> & Pick<X402AuditEntry, 'kind' | 'decision' | 'reason'>): void => {
    appendAudit(config.auditLog, {
      ts: new Date().toISOString(),
      notes: entry.notes ?? [],
      wallet_id: base.address,
      api_key_id: 'x402',
      ...entry,
    } as X402AuditEntry);
  };

  const denyThrow = (reason: string, notes: string[]): never => {
    throw new ObserverDenyError(reason, notes);
  };

  async function signTypedData(typedData: TypedDataLike): Promise<Hex> {
    const decoded = decodeX402TypedData(typedData);

    if (decoded.kind === 'cancel-authorization') {
      audit({ kind: 'typed-data', decision: 'allow', reason: `cancelAuthorization signed — ${decoded.reason}`, notes: [] });
      return base.signTypedData(typedData);
    }
    if (decoded.kind === 'eip3009-receive' || decoded.kind === 'permit2-witness') {
      const reason = `[typed-data] ${decoded.reason} — payment-bearing structure this engine cannot evaluate fails closed`;
      audit({ kind: 'typed-data', decision: 'deny', reason, notes: [] });
      return denyThrow(reason, []);
    }
    if (decoded.kind === 'unknown') {
      if (cfg.allowNonPaymentTypedData) {
        audit({ kind: 'typed-data', decision: 'allow', reason: `non-payment typed data signed UNGATED (allowNonPaymentTypedData=true): ${decoded.reason}`, notes: [] });
        return base.signTypedData(typedData);
      }
      const reason = `[typed-data] ${decoded.reason} — unknown typed data is denied by default (a payment suite this engine does not know could move funds); set allowNonPaymentTypedData=true only for flows that sign known non-payment structures`;
      audit({ kind: 'typed-data', decision: 'deny', reason, notes: [] });
      return denyThrow(reason, []);
    }

    // x402 exact/EVM payment.
    const verdict = await authorizeX402Payment(config, {
      decoded,
      walletAddress: base.address,
      ...(ledger ? { ledger } : {}),
    });
    const meta = {
      asset: decoded.verifyingContract,
      amount: decoded.value.toString(),
      recipient: decoded.to,
      nonce: decoded.nonce,
      chain_id: `eip155:${decoded.chainId}`,
    };
    if (!verdict.allow) {
      audit({ kind: 'x402-payment', decision: 'deny', reason: verdict.reason, notes: verdict.notes, ...meta });
      return denyThrow(verdict.reason, verdict.notes);
    }

    // Count the spend BEFORE producing the signature: once signed, the
    // authorization is live until validBefore and we treat it as spent.
    if (ledger) {
      const resolved = resolvedFromX402(config, decoded);
      ledger.record({
        rail: `${railLabel}:eip155:${decoded.chainId}`,
        asset: resolved.assetSymbol ?? decoded.verifyingContract,
        amountRaw: decoded.value.toString(),
        decimals: resolved.decimals ?? 0,
      });
    }
    audit({ kind: 'x402-payment', decision: 'allow', reason: verdict.reason, notes: verdict.notes, ...meta });
    return base.signTypedData(typedData);
  }

  async function signTransaction(transaction: unknown, options?: unknown): Promise<Hex> {
    if (!cfg.allowSignTransaction) {
      const reason = '[tx] signTransaction is denied by default on an x402 buyer account (payments are EIP-3009 typed data; gas is the facilitator\'s). If this flow legitimately sends transactions, gate them with mppx-op-account or ows-op-verify — enabling allowSignTransaction here signs them UNGATED.';
      audit({ kind: 'tx', decision: 'deny', reason, notes: [] });
      return denyThrow(reason, []);
    }
    audit({ kind: 'tx', decision: 'allow', reason: 'signTransaction allowed by config (NOT gated by this engine)', notes: [] });
    return base.signTransaction(transaction, options);
  }

  async function signMessage(args: { message: unknown }): Promise<Hex> {
    if (!cfg.allowSignMessage) {
      const reason = '[signMessage] raw message signing is denied by default (opaque content could authorize a payment). Set allowSignMessage=true only if this flow uses signMessage for non-payment purposes.';
      audit({ kind: 'message', decision: 'deny', reason, notes: [] });
      return denyThrow(reason, []);
    }
    audit({ kind: 'message', decision: 'allow', reason: 'raw signMessage allowed by config (NOT gated)', notes: [] });
    return base.signMessage(args);
  }

  async function sign(args: { hash: Hex }): Promise<Hex> {
    if (!cfg.allowRawSign) {
      const reason = '[raw-sign] raw hash signing is denied by default: the hash of ANY typed data can be signed this way, bypassing the signer-boundary gate. (Divergence from mppx-op-account, where the on-chain escrow still bounds spend; here the raw key is the spend authority.)';
      audit({ kind: 'raw-sign', decision: 'deny', reason, notes: [] });
      return denyThrow(reason, []);
    }
    audit({ kind: 'raw-sign', decision: 'allow', reason: 'raw hash signing allowed by config (NOT gated)', notes: [] });
    if (!base.sign) throw new Error('base account does not implement sign');
    return base.sign(args);
  }

  return {
    base,
    address: base.address,
    type: base.type,
    source: base.source,
    publicKey: base.publicKey,
    signMessage,
    signTransaction,
    signTypedData,
    sign,
  };
}
