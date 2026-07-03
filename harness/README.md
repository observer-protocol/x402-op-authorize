# Live-fire harness

Runs the engine against Cloudflare's **unmodified**
[x402-proxy-template](https://github.com/cloudflare/templates/tree/main/x402-proxy-template)
on `wrangler dev`, with the real x402@1.0.1 client doing the paying.

## Setup (once)

```sh
# 1. Get the template
git clone --depth 1 --filter=blob:none --sparse https://github.com/cloudflare/templates cf-templates
cd cf-templates && git sparse-checkout set x402-proxy-template && cd x402-proxy-template

# 2. Install (--ignore-scripts works around sharp's source build; prebuilts load fine at runtime)
npm install --ignore-scripts

# 3. Point it at the local facilitator
cat > .dev.vars << 'VARS'
JWT_SECRET=<openssl rand -hex 32>
FACILITATOR_URL=http://127.0.0.1:4021
VARS
```

## Run

```sh
node harness/local-facilitator.mjs &        # :4021 — REAL EIP-712 verification, SIMULATED settlement
(cd …/x402-proxy-template && npx wrangler dev --port 8787) &
node harness/livefire-client.mjs            # scenarios A (allow/200), B (deny at key), C (x402.org probe)
node demo/cross-rail.mjs                    # the flagship: one $5 budget, two rails, both deny over-budget
```

To exercise REAL on-chain settlement instead: remove `FACILITATOR_URL` from
`.dev.vars` (the template then uses https://x402.org/facilitator), fund the
buyer wallet with Base Sepolia USDC (Circle faucet), and export its key as
`PRIVATE_KEY` for a fixed (non-ephemeral) buyer. Everything else is unchanged.
