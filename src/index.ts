// @observer-protocol/x402-op-authorize
//
// Observer Protocol authorization for x402 payments, at the signer boundary.
// Wrap the agent's viem account with createObserverX402Account and hand the
// result to any x402 client (x402-fetch, x402-axios, x402/client
// createPaymentHeader, Cloudflare Agents SDK payments) — every EIP-3009
// payment authorization is evaluated against the agent's signed, revocable
// delegation before a signature exists. Deny means the payment was never
// signed, so it can never settle.

export { createObserverX402Account } from './account.js';
export type { ObserverX402Account } from './account.js';

export { authorizeX402Payment, resolvedFromX402 } from './buyer.js';
export type { X402AuthInput } from './buyer.js';

export { decodeX402TypedData, X402_EVM_TOKENS } from './x402.js';
export type { DecodedX402 } from './x402.js';

export { ObserverDenyError } from './adapter-types.js';
export type {
  BaseAccount,
  TypedDataLike,
  ObserverX402AccountConfig,
  Hex,
  Address,
} from './adapter-types.js';
