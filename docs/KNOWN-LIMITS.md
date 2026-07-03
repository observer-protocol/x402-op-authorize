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
6. **Demo settlement is simulated.** The live-fire facilitator
   (harness/local-facilitator.mjs) performs REAL EIP-712 signature
   verification of the exact emitted payload and the real x402.org facilitator
   was probed with the same bytes (signature accepted; unfunded testnet wallet
   → insufficient_balance, as expected). The only unexercised hop is the
   on-chain `transferWithAuthorization` broadcast — fund a Base Sepolia USDC
   wallet to close it (TESTING.md in Cloudflare's template).
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
10. **Schema v2.2 URL is minted, not yet published.** The credential schema
    file (docs/schemas/delegation-v2.2.json) must be published at
    https://observerprotocol.org/schemas/delegation/v2.2.json before external
    parties can resolve it. v2.1 is frozen forever, unchanged, per the schema
    immutability policy.
