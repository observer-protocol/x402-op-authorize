export type CancelVerdictResolver = (facts: {
  /** From the CancelAuthorization payload. Whose authorization is being revoked. */
  authorizer: string | undefined;
  /** From the CancelAuthorization payload. WHICH authorization. */
  nonce: string | undefined;
}) => Promise<{ allow: boolean; reason: string }>;

// The viem custom-account seam for x402 buyers. Runtime is dependency-free;
// `viem` is a TYPES-ONLY peer. We model the slice of the viem account
// interface an x402 client invokes, structurally, so a wrapped viem
// LocalAccount satisfies BaseAccount by shape (same pattern as
// mppx-op-account/adapter-types.ts).

export type Hex = `0x${string}`;
export type Address = `0x${string}`;

/** The structural slice of a viem account x402 clients invoke. x402's
 * `createPaymentHeader` / `wrapFetchWithPayment` call signTypedData for the
 * EIP-3009 authorization; everything else is gated defensively. */
export interface BaseAccount {
  address: Address;
  type?: string;
  source?: string;
  publicKey?: Hex;
  signMessage: (args: { message: unknown }) => Promise<Hex>;
  signTransaction: (transaction: unknown, options?: unknown) => Promise<Hex>;
  signTypedData: (typedData: TypedDataLike) => Promise<Hex>;
  sign?: (args: { hash: Hex }) => Promise<Hex>;
}

/** EIP-712 typed data as handed to account.signTypedData. The x402 exact/EVM
 * authorization arrives here — from/to/value/validAfter/validBefore/nonce are
 * FIELDS of `message`, already structured; no ABI/byte decode is needed. */
export interface TypedDataLike {
  domain?: {
    name?: string;
    version?: string;
    chainId?: number | bigint | string;
    verifyingContract?: Address;
    [k: string]: unknown;
  };
  types?: Record<string, Array<{ name: string; type: string }>>;
  primaryType?: string;
  message?: Record<string, unknown>;
}

export interface ObserverX402AccountConfig {
  /** The OP verifier policy object — identical vocabulary to the other OP
   * engines (parsed by the shared parseConfig): credentialPath, issuerDid,
   * schemaAllowlist, rails, evmTokens, revocation, auditLog, etc. */
  policy: Record<string, unknown>;
  /** Path to the shared cross-rail spend ledger (CrossRailLedger JSONL). The
   * account reads rolling-24h totals from it before every signature and
   * records every allowed payment into it. REQUIRED for mandates that carry
   * tradingMandate.crossRailBudget or velocity caps — such a mandate with no
   * ledger fails closed (no counter can be established). */
  crossRailLedgerPath?: string;
  /** Rail label prefix for ledger entries; default "x402". Entries are
   * written as `${railLabel}:${caip2}` (e.g. "x402:eip155:84532"). */
  railLabel?: string;
  /** Allow raw (non-typed) signMessage. DENIED by default: its content is
   * opaque and could encode a payment commitment. */
  allowSignMessage?: boolean;
  /** Allow signTransaction. DENIED by default: an x402 buyer account has no
   * business signing transactions (payments are EIP-3009 typed data, gas is
   * the facilitator's). If your flow needs it, it is NOT decoded or gated by
   * this engine — compose mppx-op-account or ows-op-verify for that surface. */
  allowSignTransaction?: boolean;
  /** Allow raw hash signing via account.sign. DENIED by default: a raw hash
   * can be the hash of ANY typed data, so passing it through would bypass the
   * signer-boundary gate entirely. (Deliberate divergence from mppx, which
   * passes base.sign through — on Tempo the escrow bounds spend on-chain; in
   * x402 the raw key IS the spend authority.) */
  allowRawSign?: boolean;
  /** Allow typed data this engine does not recognize as payment-bearing.
   * DENIED by default: Permit2-style suites move funds and new payment
   * suites appear; unknown typed data is unprovably safe. Enable only for
   * flows that sign known non-payment structures, and accept they are NOT
   * gated. */
  allowNonPaymentTypedData?: boolean;

  /** Who decides whether a cancellation may be signed. Supplied by a host that holds the mandate
   * and the reservation record.
   *
   * ABSENT MEANS THIS DEPLOYMENT HAS NOBODY TO ASK, and the behaviour is unchanged: the
   * cancellation is signed, and the audit entry records that no verdict was obtained. That is a
   * deliberate choice between two known-wrong behaviours.
   *
   * Denying instead would break legitimate housekeeping on every library deployment on the default
   * config, and would be the third arrival of a blanket refusal already rejected twice. Signing
   * unevaluated is the shipped behaviour, bounded by cancellation moving no money, and it is now
   * VISIBLE PER EVENT rather than silent.
   *
   * TWO FACTS ABOUT TWO DEPLOYMENTS, NOT ONE FACT UPDATED, which is the same shape as X402-P2 and
   * X402-P3 in the registry. A service that holds the mandate wires this and the path closes. A
   * library linked into a caller's process has no service to ask and the path stays open. Both are
   * true, and collapsing them to "closed" would be false about the published package. */
  resolveCancelVerdict?: CancelVerdictResolver;
}

export class ObserverDenyError extends Error {
  readonly code = 'OBSERVER_POLICY_DENY';
  readonly reason: string;
  readonly notes: string[];
  constructor(reason: string, notes: string[]) {
    super(reason);
    this.name = 'ObserverDenyError';
    this.reason = reason;
    this.notes = notes;
  }
}

/** Ask the host whether a cancellation may be signed.
 *
 * WHY THIS IS A CALLBACK AND NOT A DECISION MADE HERE. X402-D5 was not a missing evaluation, it
 * was a missing route: cancellation lived entirely inside this adapter's signTypedData, so the
 * thing holding the mandate, the reservation record and the approval history was never asked.
 *
 * Every attempt to answer it HERE gave the adapter facts it should not hold in order to make a
 * decision that was never its to make, and each shape failed closed, because the adapter genuinely
 * cannot answer: resolving provenance means deriving a request identity from the mandate, the
 * credential digest and the reservation record, none of which a signer holds.
 *
 * So the adapter DECODES AND REPORTS; the host DECIDES. Same direction as everything else here:
 * the verdict arrives attached rather than being computed at the signer. */
