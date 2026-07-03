# Support matrix — x402-op-authorize v0.1

## Enforcement coverage at the signer boundary

| Surface | Coverage |
|---|---|
| EIP-3009 TransferWithAuthorization (x402 exact/EVM, v1 + v2 wire) | ENFORCED — full shared mandate: per-payment ceiling (`maxNotionalPerOrder` / `per_transaction_ceiling`), counterparty allow/block (signed `to`), temporal windows, velocity (`dailyVolumeCap` via rolling-24h same-asset ledger view), crossRailBudget (v2.3), allowed_rails, authorization-level configs; credential integrity (proof, expiry, revocation, issuer pin, schema allowlist, signer-boundary) |
| authorization.from ≠ wrapped wallet | DENY (never sign transfers out of another wallet) |
| validBefore in the past | DENY (dead authorization) |
| Unknown token contract | unenforceable → DENY under any binding amount/counterparty constraint |
| Unmapped chainId | DENY (`[rails]`) |
| ReceiveWithAuthorization / PermitWitnessTransferFrom | DENY (payment-bearing, undecoded in v1) |
| CancelAuthorization | ALLOW (moves no funds), audited |
| Unknown typed data | DENY by default; `allowNonPaymentTypedData` opts out UNGATED |
| signTransaction / signMessage / raw sign | DENY by default; knobs opt out UNGATED |

## Counters

| Counter | Source | Semantics |
|---|---|---|
| Same-asset velocity | shared ledger `sumWindowRaw` | rolling 24h ⊇ calendar day → trips early, never late |
| Cross-rail budget | shared ledger `sumWindowConverted` at mandate rates | round-up conversion; unpriceable in-window entry ⇒ total unestablishable ⇒ DENY |
| Spend recording | at signature time (x402) / at hook-allow (l402) | signature = spend commitment; conservative overcount on client re-sign |

## Verification status (2026-07-03)

| Claim | Status |
|---|---|
| 40/40 engine conformance (allow + deny per rule) | GREEN (`npm test`) |
| 245/245 parity harness, 5 engines, shared core | GREEN |
| Live-fire vs unmodified Cloudflare x402-proxy-template (wrangler dev), x402@1.0.1 client | GREEN — 402→sign→X-PAYMENT→verify→settle→200; deny side: ObserverDenyError inside the client, no signature, resource stays 402 |
| Facilitator verification of the exact emitted payload | GREEN — local facilitator does real EIP-712 recovery; real x402.org facilitator verified + settled the same bytes (post-settle probe returns `nonce_already_used`: the authorization is provably consumed on-chain) |
| On-chain settlement (Base Sepolia broadcast) | GREEN (2026-07-03) — real x402.org facilitator settled the demo's three $0.01 legs on-chain (blocks 43667763–64, payer 0x58Aa…6C07 → payTo, buyer wallet holds ZERO ETH: EIP-3009 payer-gasless proven) |
| Cross-rail demo (one $5 budget, THREE rails: USDC-on-Base via the Cloudflare template + Lightning via the l402 hook + USDT-on-TRON via the real WDK policy engine; all three deny over-budget) | GREEN — `demo/TRANSCRIPT.txt` |
