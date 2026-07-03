# Known limits (v0.1)

Stated plainly, per house rule: path-green is not component-green, and a limit
that isn't written down is a claim we didn't earn.

1. **LINK full-mode is a fail-closed scaffold.** The shared core's
   BIND→LINK→AUTHORIZE RuntimeAdapter verifies principal↔agent linkage by DID
   equality in dev mode only; full-mode (L1 principal-binding chain /
   cosign_verify) DENIES until wired. This engine's demo and tests run did:key
   dev-mode issuance. (Additionally, this engine calls
   verifyCredential+enforceMandate directly — the WBC wallet-binding step is
   not yet in its path because the shared parseConfig strips the WBC keys;
   roadmap item to thread RuntimeAdapterConfig through.)
2. **Permit2 and `upto` are denied, not decoded.** x402's `exact` Permit2
   fallback and the `upto` scheme sign `PermitWitnessTransferFrom` typed data.
   The engine recognizes and DENIES them (payment-bearing, unevaluated). A
   future decoder must count the SIGNED maximum (`permitted.amount`), not the
   settled amount, into velocity/budget — the signature is the spend authority.
   Same for EIP-3009 `receiveWithAuthorization`.
3. **Counting is conservative by construction.** A signed authorization is
   counted as spent at signature time (it is live until `validBefore`; the
   facilitator controls settlement timing). Client retries that re-sign with a
   new nonce each count separately. The budget trips early, never late.
4. **The l402 hook counts at allow-time.** lnget has no post-payment callback,
   so an allowed Lightning payment consumes budget even if the payment later
   fails. Reserve/commit/release exists in the ledger API for callers that can
   confirm settlement.
5. **Decision log is unsigned JSONL.** Signed PolicyEvaluationCredential
   emission (key-3, via the policy sidecar's /evaluate) is the service-tier
   path; wiring this engine's verdicts through it is roadmap.
6. **Settlement fidelity is configuration-dependent — and the real path is
   CLOSED.** With harness/local-facilitator.mjs, settlement is simulated
   (signature verification still real). With the template pointed at the
   real x402.org facilitator and a funded wallet, the full loop is proven:
   on 2026-07-03 the demo's three $0.01 legs settled as real Base Sepolia
   USDC transfers (blocks 43667763–64) from a buyer wallet holding zero ETH
   — EIP-3009's payer-gasless property demonstrated on-chain.
7. **v1 wire in the harness.** The Cloudflare template speaks x402Version 1
   (x402@1.0.1, X-PAYMENT header). x402 v2 (CAIP-2 networks,
   PAYMENT-SIGNATURE header) signs the SAME EIP-3009 typed data, so the
   signer-boundary gate is wire-version-independent; a v2 harness run is
   still owed when the template migrates.
8. **`cloudflare:402` batch-settlement is a different signer boundary.**
   Cloudflare's own pay-per-crawl rail authenticates with RFC-9421 HTTP
   Message Signatures (credit-backed, no per-payment on-chain settle). The
   same OP gate belongs in front of that signing key; it is scoped as a
   follow-on engine, not this one.
9. **Rolling-24h "day".** Both counters (velocity, cross-rail) use a rolling
   24h window here; the core's velocity note documents calendar-day counters
   elsewhere. Rolling ⊇ calendar-day, so this only ever denies earlier.
10. **TRON leg fidelity.** The demo's USDT-TRON leg runs through the REAL
    merged WDK policy engine (PR #55) and the real OP ALLOW/DENY pair on a
    mock TRON account — the same fidelity as wdk-op-policy's conformance
    suite; no chain broadcast. wdk-op-policy has never been live-fired
    against `@tetherto/wdk-wallet-tron` itself (beta.7, vs wdk-wallet base
    beta.10) — verify version alignment at the first live TRON deployment.
11. **Schema v2.2 URL is minted, not yet published.** The credential schema
    file (docs/schemas/delegation-v2.2.json) must be published at
    https://observerprotocol.org/schemas/delegation/v2.2.json before external
    parties can resolve it. v2.1 is frozen forever, unchanged, per the schema
    immutability policy.
