# Fidelity notes — cross-rail demo settlement evidence

Every on-chain claim made about this demo, with the evidence to check it
yourself. Buyer wallet: `0x58Aa16206103c4eacd0461370a91acd81B316C07`
(Base Sepolia; holds **zero ETH** at all times — x402 exact/EVM is EIP-3009
`transferWithAuthorization`, the facilitator broadcasts and pays gas).
Asset: Base Sepolia USDC `0x036CbD53842c5426634e7929541eC2318f3dCF7e`.
Verify any row at `https://sepolia.basescan.org/tx/<hash>`, or independently:

```
eth_getLogs topics=[Transfer, from=0x…58Aa16206103c4eacd0461370a91acd81B316C07]
against the USDC contract above.
```

## What is real vs. what can be simulated

The engine and mandate evaluation are identical in every configuration. The
**settlement hop** depends on which facilitator the seller (Cloudflare's
unmodified x402-proxy-template) is pointed at:

- **Real** (`FACILITATOR_URL` unset → production `x402.org/facilitator`):
  verification and on-chain settlement by Coinbase's production facilitator.
  All takes below ran this way.
- **Local CI** (`harness/local-facilitator.mjs`): real EIP-712 signature
  verification, simulated settlement (no chain write). Used only for
  self-contained CI runs; never for the takes recorded here.

Deny-side legs never reach a facilitator in either mode: a denied payment is
never signed, so there is nothing to verify or settle.

## Settlement ledger (all takes, 2026-07-03, $0.01 USDC each)

**Take 1 — first real-settle run** (demo legs A/D/E):
| block | tx |
|---|---|
| 43667763 | `0xf47250a803fb662df22ad02ceae77bbd0ca42e9a5caf809d475719463ae2dcce` |
| 43667763 | `0x18c49563643c23f6bd90e714a69ae9fc5dbf37c00a236fcc3a8fceaa3bc867f0` |
| 43667764 | `0xbf7b215224061298746361be8b7b7349875375cdcfaa32065c201d8b7dd43998` |

**Take 2 — transcript capture + live-fire** (3 demo legs + 1 live-fire):
blocks 43667787–43667788 (`0x3a64bb8e…`, `0x3cdf5138…`, `0x80843454…`,
`0x31aaccc6…`) and 43667813 (`0xed570057…`, live-fire re-capture).
**Post-settlement probe observation:** re-submitting take 2's already-settled
scenario-A payload to `x402.org/facilitator/verify` returned
`{"isValid":false,"invalidReason":"invalid_exact_evm_nonce_already_used"}` —
the production facilitator attesting that the EIP-3009 authorization was
consumed on-chain. (A probe that races settlement can instead return
`{"isValid":true}`, as in the committed transcript's take: verify is a
point-in-time check, the settle receipts are the durable evidence.)

**Take 3 — v2.3 schema re-capture, flaked** (2 of 3 legs settled; one leg
verify-rejected by the facilitator on a sub-second `validAfter` clock-skew,
the known x402-v1 flake; the take was discarded and re-run):
blocks 43668618–43668619 (`0x98ef2cbd…`, `0xcaeffc57…`, `0x3febd400…`).

**Take 4 — v2.3 re-capture, superseded by take 5** (3 demo legs + 1 live-fire):
| block | tx |
|---|---|
| 43668674 | `0xb5075d7d009e0d98dbfee32d6c199ecb74cb638233a53aa770594f2c4be9b9f5` |
| 43668674 | `0x8ce5490585fd2e2ae08f64d3e1520eeea8362edf6a4108ee77281b04f16f924a` |
| 43668674 | `0xf88a38dec78c8ffe4dae3e8a649b7e4dddbb06f2058dbaf0b8a2cfb2cd1f5ebb` |
| 43668675 | `0xa11d4124267887fe7d6c43b60e48c2e9f0143606ac34e7edd1d58e22bb546aae` |

**Take 5 — the committed `TRANSCRIPT.txt` (2026-07-06, launch capture)**
(3 demo legs + 1 live-fire; one earlier live-fire attempt in this session
verify-rejected on the same clock-skew flake — signed, never settled, no
chain trace, budget consumed per the rule below):
| block | tx |
|---|---|
| 43793016 | `0x470b92944a07283b9509e2a3da65dad0f4eed03ac30f988734ce7b6fe09203de` |
| 43793016 | `0xdcacc4e5e5083243cf6b48838f03e3603d9847b402323abaae1a454f481661e7` |
| 43793017 | `0xb5c9bac137acb361d537a89e89ce7b8925f44912be790d6e8173036fcd7e4226` |
| 43793058 | `0x4167c75c2c748ab119a4326f19d1526f1f4c58a9d5ae1855be027ee81c38a50b` |

Take 4's last hash remains visible in take 4's superseded transcript
(`tx=0xa11d4124267887fe…`); take 5 is the committed one. A signed-but-flaked leg still consumes its amount
from the cross-rail budget (a signed authorization is live spend authority
until `validBefore`) — the budget trips early, never late, by design.
