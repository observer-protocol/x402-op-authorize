# x402-op-authorize

**The x402 instance of [OP Crossrail](https://observerprotocol.org)** — Observer Protocol's cross-rail authorization layer. Crossrail is one signed mandate, one rolling budget, and one shared spend ledger enforced across every rail an agent pays on; this engine enforces it at the x402 signer boundary. Same shared `@observer-protocol/policy-engine` core as the OWS, mppx/Tempo, Tether-WDK and L402/Lightning instances — only the decoder changed.

x402 (the protocol behind Cloudflare's Monetization Gateway and Coinbase's payment stack) makes the payment prove **funds**. It does not prove **authority**: nothing in the flow checks that the agent was authorized by its principal to spend, at what cap, on what. This engine closes that gap on the buyer side, where the one structural chokepoint lives: an x402 exact/EVM payment IS an EIP-3009 `transferWithAuthorization` signature. Interpose there and a denied payment never exists — not "rejected", not "reverted": **never signed**.

```js
import { privateKeyToAccount } from 'viem/accounts';
import { createObserverX402Account } from '@observer-protocol/x402-op-authorize';

const account = createObserverX402Account(privateKeyToAccount(PRIVATE_KEY), {
  policy: {
    credentialPath: '/path/to/agent-delegation.json', // signed, revocable OP delegation
    issuerDid: 'did:key:z6Mk…',                       // pinned principal
    agentDid: 'did:key:z6Mk…',
    schemaAllowlist: [
      'https://observerprotocol.org/schemas/delegation/v2.3.json',
      'https://observerprotocol.org/schemas/delegation/v2.4.json',
    ],
    rails: { 'eip155:8453': { rail: 'base-mainnet', currency: 'ETH', decimals: 18, family: 'evm' } },
    auditLog: '/var/lib/op/decisions.jsonl',
    cacheDir: '/var/lib/op/cache',
    allowContractCalls: false,
    revocation: { maxStalenessHours: 24, onUnreachable: 'cache-then-deny', fetchTimeoutMs: 1500 },
    didCache: { maxStalenessHours: 24 },
  },
  crossRailLedgerPath: '/var/lib/op/cross-rail-ledger.jsonl',
});

// Hand `account` to ANY x402 client — zero changes to those libraries:
//   x402/client createPaymentHeader, x402-fetch wrapFetchWithPayment,
//   x402-axios, Cloudflare Agents SDK payments.
```

Every `signTypedData` call is classified. x402 payments (EIP-3009 `TransferWithAuthorization`) are evaluated against the agent's signed delegation — per-payment ceiling, counterparty (the **signed** `to`, never the 402 body's claims), velocity, cross-rail budget, credential validity/revocation/signer-boundary — fail-closed on every miss. Recognized payment suites this engine does not decode (Permit2, `receiveWithAuthorization`) deny. Unknown typed data denies by default. `signTransaction`, `signMessage` and raw `sign` deny by default.

## OP Crossrail: one budget, every rail

Schema v2.3 adds `tradingMandate.crossRailBudget`: one rolling-24h budget consumed across **all** rails a delegation spans, converted at rates the principal attests **inside the signed credential** — no FX feed, no oracle, nothing unsigned in the evaluation path:

```json
"crossRailBudget": { "amount": "5", "currency": "USD", "window": "P1D",
                     "rates": { "USDC": "1", "sat": "0.0005" } }
```

Three buyer gates (`x402-op-authorize`, `l402-op-authorize`, `wdk-op-policy`) share one append-only ledger. `demo/cross-rail.mjs` runs the full story: a $5 budget consumed to exactly $5.00 across **USDC on Base** (via Cloudflare's **unmodified** [x402-proxy-template](https://github.com/cloudflare/templates/tree/main/x402-proxy-template)), **Lightning** (via the lnget pre-payment hook), and **USDT on TRON** (via Tether's real merged WDK policy engine). After that, every rail refuses: the x402 attempt dies **at the key** (no signature ever exists; the resource stays 402), the Lightning attempt dies at the hook, and the TRON transfer dies inside the WDK engine's fail-closed DENY rule with the base transfer never invoked. USDT carries its own attested rate (explicitly `"1"` — no implicit peg-equivalence with USDC anywhere in the evaluator). Transcript: `demo/TRANSCRIPT.txt`.

## Enforcement-locus claim discipline

- **Hard-binding, key-bound** — only where this account wrapper IS the signer (self-custodial viem accounts). There, "deny means the signature never exists" is exact.
- **Not claimed** — agents paying through custodial or facilitator-held keys OP does not wrap. Label such deployments policy-tier.
- **Out of scope** — seller-side x402 gating (Cloudflare's domain), `cloudflare:402` batch-settlement (an RFC-9421 HTTP-signature rail — a different signer boundary, see docs/SCOPE.md), Permit2/`upto` decode (deny today, decode later).

## Test

```
npm test                      # 40/40 conformance cases (allow + deny per rule)
node ../op-policy-engine/packages/parity-harness/run.mjs   # 245 cases, 5 engines
```

Live-fire against the Cloudflare template: `harness/README.md`.

MIT © Observer Protocol, Inc.
