// x402 decoder: classify EIP-712 typed data handed to the wrapped account and,
// for the x402 exact/EVM payment (EIP-3009 transferWithAuthorization), extract
// the engine's common evaluation input. This is the "only the decoder changed"
// layer — verification + mandate enforcement below it is the shared
// @observer-protocol/policy-engine core, identical to l402-op-authorize,
// mppx-op-account and ows-op-verify.
//
// Everything here reads the RAW SIGNED PAYLOAD, never the 402 response body:
// the chain is domain.chainId, the asset is domain.verifyingContract, the
// counterparty is message.to, the amount is message.value. What the server
// *claimed* in `accepts[]` is irrelevant — the signature is the authority.

import type { TypedDataLike } from './adapter-types.js';

/** ERC-20 contracts x402 volume actually moves on, beyond the shared core's
 * DEFAULT_EVM_TOKENS (which covers mainnets). Testnet contracts live here so
 * a demo config works out of the box; deployments extend via policy.evmTokens. */
export const X402_EVM_TOKENS: Record<string, { symbol: string; decimals: number }> = {
  // Base Sepolia USDC (Circle testnet deployment; the x402 default testnet asset)
  '0x036cbd53842c5426634e7929541ec2318f3dcf7e': { symbol: 'USDC', decimals: 6 },
};

export type DecodedX402 =
  | {
      kind: 'eip3009-transfer';
      from: string;
      to: string;
      value: bigint;
      validAfter: bigint;
      validBefore: bigint;
      nonce: string;
      chainId: number;
      verifyingContract: string;
      domainName?: string;
    }
  | { kind: 'eip3009-receive'; reason: string }
  | { kind: 'permit2-witness'; reason: string }
  | { kind: 'cancel-authorization'; reason: string }
  | { kind: 'unknown'; reason: string };

function asBigInt(v: unknown): bigint | undefined {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  if (typeof v === 'string' && /^\d+$/.test(v)) return BigInt(v);
  return undefined;
}

function asAddress(v: unknown): string | undefined {
  return typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v) ? v : undefined;
}

/** Classify typed data. Payment-bearing suites we cannot (yet) decode are
 * named explicitly so the deny reason says what arrived; everything
 * unrecognized is 'unknown' (deny by default at the account layer). */
export function decodeX402TypedData(td: TypedDataLike): DecodedX402 {
  const pt = td?.primaryType;
  if (pt === 'ReceiveWithAuthorization') {
    return { kind: 'eip3009-receive', reason: 'EIP-3009 receiveWithAuthorization moves funds and is not part of the x402 exact/EVM flow this engine decodes' };
  }
  if (pt === 'PermitWitnessTransferFrom') {
    return { kind: 'permit2-witness', reason: 'Permit2 permitWitnessTransferFrom moves funds (x402 permit2 / upto asset-transfer methods) — not decoded in v1' };
  }
  if (pt === 'CancelAuthorization') {
    return { kind: 'cancel-authorization', reason: 'EIP-3009 cancelAuthorization revokes an outstanding authorization and moves no funds' };
  }
  if (pt !== 'TransferWithAuthorization') {
    return { kind: 'unknown', reason: `primaryType ${JSON.stringify(pt ?? null)} is not a payment structure this engine recognizes` };
  }

  const m = td.message ?? {};
  const from = asAddress(m['from']);
  const to = asAddress(m['to']);
  const value = asBigInt(m['value']);
  const validAfter = asBigInt(m['validAfter']);
  const validBefore = asBigInt(m['validBefore']);
  const nonce = typeof m['nonce'] === 'string' ? m['nonce'] : undefined;
  const verifyingContract = asAddress(td.domain?.verifyingContract);
  const chainId = td.domain?.chainId !== undefined ? Number(td.domain.chainId) : undefined;

  if (!from || !to || value === undefined || validAfter === undefined || validBefore === undefined || !nonce || !verifyingContract || chainId === undefined || !Number.isSafeInteger(chainId)) {
    return { kind: 'unknown', reason: 'TransferWithAuthorization typed data is missing or malforms required fields (from/to/value/validAfter/validBefore/nonce/domain.chainId/domain.verifyingContract) — undecodable payment fails closed' };
  }

  return {
    kind: 'eip3009-transfer',
    from,
    to,
    value,
    validAfter,
    validBefore,
    nonce,
    chainId,
    verifyingContract: verifyingContract.toLowerCase(),
    domainName: typeof td.domain?.name === 'string' ? td.domain.name : undefined,
  };
}
