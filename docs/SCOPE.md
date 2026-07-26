# SCOPE — x402-op-authorize v0.1

## §1 What this engine is

Buyer-side Observer Protocol enforcement for x402 payments, at the signer
boundary. An x402 `exact`/EVM payment is authorized by an EIP-3009
`transferWithAuthorization` EIP-712 signature produced by the buyer's key. This
engine wraps that key (viem custom-account seam, identical to
mppx-op-account's) and evaluates the agent's signed, revocable delegation
against the RAW SIGNED FIELDS before any signature exists. Deny at this locus
means the payment can never settle, on any facilitator, ever — there is
nothing to broadcast.

## §2 No-merge composition

Zero changes to any x402 library. `createObserverX402Account(base, cfg)`
returns a structural viem account; every x402 client that takes an account
(`x402/client` `createPaymentHeader`, `x402-fetch`, `x402-axios`) composes
with it unmodified. Cloudflare's Agents SDK payment client also takes a viem
signer and is expected to compose, but it has not been live-fired here, so it
is not listed as a supported surface (see SUPPORT-MATRIX for what has).
Same discipline as the l402 engine's lnget env hook and the WDK policy pair.

## §3 Source of truth: the signed payload, never the 402 body

Chain = `domain.chainId`. Asset = `domain.verifyingContract` (resolved through
the pinned token registry). Counterparty = `message.to`. Amount =
`message.value`. Validity = `message.validAfter/validBefore`. What the seller
CLAIMED in `accepts[]` is not consulted for enforcement — a lying server
cannot widen its own authorization. This is the enforcement-locus discipline
(raw payload at the signer) that differentiates every OP engine.

## §4 Typed-data classification (fail-closed)

| primaryType | class | verdict |
|---|---|---|
| TransferWithAuthorization | x402 exact/EVM payment | full mandate evaluation |
| ReceiveWithAuthorization | payment-bearing, undecoded | DENY |
| PermitWitnessTransferFrom | Permit2 (`exact` fallback / `upto`) | DENY (v1) |
| CancelAuthorization | revokes an outstanding authorization | ALLOW, audited |
| anything else | unprovably safe | DENY (knob: `allowNonPaymentTypedData`) |

`signTransaction`, `signMessage`, raw `sign` — DENY by default. Raw `sign` is
a deliberate divergence from mppx-op-account (there the on-chain escrow bounds
spend; here the raw key IS the spend authority, and a raw hash can be the hash
of any typed data).

## §5 Identity

Issuer pinned by config; did:key resolves offline, did:web via the shared
resolver. eddsa-jcs-2022 proofs only. Signer-boundary check denies
agent-self-issued mandates. Dev-mode issuance (did:key operator) for the demo;
full-mode L1 principal-binding is the shared core's scaffold (KNOWN-LIMITS §1).

## §6 Cross-rail budget (G8)

Schema v2.3 `tradingMandate.crossRailBudget` + the shared `CrossRailLedger`
(policy-engine core): one rolling-24h budget across every rail the delegation
spans. Rates are principal-attested inside the signed credential — the
evaluator is oracle-free and the AIP v0.8 same-currency invariant holds
(every comparison happens in the budget currency on signed data). Round-up
conversion; unpriceable in-window spend poisons the total → deny. The l402
engine consumes the same ledger (its hook records allowed Lightning spends).

## §7 Out of scope (v1)

- Seller-side x402 gating — Cloudflare's Monetization Gateway does this at the
  edge; we do not compete on that side. (A seller-side OP verification hook —
  gate/price on verified agent credentials — is the Phase-3 ecosystem play.)
- `cloudflare:402` batch-settlement — Cloudflare's pay-per-crawl rail signs
  HTTP requests (RFC 9421) against a registered signature-agent key,
  credit-backed. That key is ALSO a signer boundary and belongs behind the
  same OP gate, as its own engine.
- Permit2 / `upto` / `receiveWithAuthorization` decode (denied today).
- Solana (`exact`/SVM) — different signer surface entirely.
- x402-Stripe fiat settlement — no client signing moment; that is Arbis's
  runtime-hold chokepoint, not ours.
