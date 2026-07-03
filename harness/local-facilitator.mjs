// Local x402 facilitator for live-fire testing (v1 wire).
//
// /verify performs REAL verification of the exact payload the buyer emitted:
// EIP-712 signature recovery (viem verifyTypedData) against the EIP-3009
// TransferWithAuthorization message, payTo/amount/validity-window checks
// against the payment requirements. /settle re-verifies and then SIMULATES
// settlement (no chain write) — the returned transaction hash is a digest of
// the signature, clearly not an on-chain tx. This keeps the full
// 402 → sign → X-PAYMENT → verify → 200 loop honest about what is real
// (client signature, server middleware, facilitator verification) and what is
// simulated (the on-chain transferWithAuthorization broadcast only).
//
// Usage: node harness/local-facilitator.mjs   (PORT env, default 4021)
import http from 'node:http';
import { createHash } from 'node:crypto';
import { verifyTypedData } from 'viem';

const PORT = parseInt(process.env.PORT || '4021', 10);

const NETWORK_CHAIN_IDS = { 'base-sepolia': 84532, base: 8453 };

const AUTH_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
};

async function checkPayment(paymentPayload, paymentRequirements) {
  const req = paymentRequirements ?? {};
  const chainId = NETWORK_CHAIN_IDS[req.network];
  if (paymentPayload?.scheme !== 'exact' || !chainId) {
    return { isValid: false, invalidReason: 'unsupported_scheme' };
  }
  const auth = paymentPayload?.payload?.authorization;
  const signature = paymentPayload?.payload?.signature;
  if (!auth || !signature) return { isValid: false, invalidReason: 'invalid_payload' };

  const message = {
    from: auth.from,
    to: auth.to,
    value: BigInt(auth.value),
    validAfter: BigInt(auth.validAfter),
    validBefore: BigInt(auth.validBefore),
    nonce: auth.nonce,
  };
  let recovered = false;
  try {
    recovered = await verifyTypedData({
      address: auth.from,
      domain: {
        name: req.extra?.name,
        version: req.extra?.version,
        chainId,
        verifyingContract: req.asset,
      },
      types: AUTH_TYPES,
      primaryType: 'TransferWithAuthorization',
      message,
      signature,
    });
  } catch (e) {
    return { isValid: false, invalidReason: `invalid_signature: ${e.message}` };
  }
  if (!recovered) return { isValid: false, invalidReason: 'invalid_signature' };
  if (auth.to.toLowerCase() !== String(req.payTo).toLowerCase()) {
    return { isValid: false, invalidReason: 'invalid_recipient' };
  }
  if (BigInt(auth.value) < BigInt(req.maxAmountRequired)) {
    return { isValid: false, invalidReason: 'insufficient_amount' };
  }
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (message.validAfter > now) return { isValid: false, invalidReason: 'authorization_not_yet_valid' };
  if (message.validBefore <= now) return { isValid: false, invalidReason: 'authorization_expired' };
  return { isValid: true, payer: auth.from };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

const send = (res, code, body) => {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://127.0.0.1:${PORT}`);
  if (req.method === 'GET' && url.pathname === '/supported') {
    return send(res, 200, { kinds: [{ x402Version: 1, scheme: 'exact', network: 'base-sepolia' }] });
  }
  if (req.method === 'POST' && (url.pathname === '/verify' || url.pathname === '/settle')) {
    let parsed;
    try {
      parsed = JSON.parse(await readBody(req));
    } catch {
      return send(res, 400, { isValid: false, invalidReason: 'malformed_body' });
    }
    const { paymentPayload, paymentRequirements } = parsed;
    const verdict = await checkPayment(paymentPayload, paymentRequirements);
    const auth = paymentPayload?.payload?.authorization ?? {};
    console.log(`[facilitator] ${url.pathname} from=${auth.from} to=${auth.to} value=${auth.value} → ${verdict.isValid ? 'signature VERIFIED (real EIP-712 recovery)' : 'REJECTED: ' + verdict.invalidReason}`);
    if (url.pathname === '/verify') return send(res, 200, verdict);
    if (!verdict.isValid) {
      return send(res, 200, { success: false, errorReason: verdict.invalidReason, transaction: '', network: paymentRequirements?.network });
    }
    const simTx = '0x' + createHash('sha256').update(paymentPayload.payload.signature).digest('hex');
    console.log(`[facilitator] settle SIMULATED (no chain write) tx=${simTx.slice(0, 18)}…`);
    return send(res, 200, { success: true, transaction: simTx, network: paymentRequirements.network, payer: verdict.payer });
  }
  send(res, 404, { error: 'not found' });
});

server.listen(PORT, () => console.log(`[facilitator] local x402 facilitator on :${PORT} — REAL signature verification, SIMULATED settlement`));
