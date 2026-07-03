// Test/demo issuance helpers for the x402 engine: did:key generation and
// eddsa-jcs-2022 credential signing. The ENGINE only verifies; this is the
// issuer/holder side tooling tests + the demo use. Run standalone, it writes
// inspectable sample fixtures to ./out/.
import { generateKeyPairSync, sign as edSign, createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function b58(buf) {
  let x = 0n;
  for (const b of buf) x = x * 256n + BigInt(b);
  let o = '';
  while (x > 0n) { o = A[Number(x % 58n)] + o; x /= 58n; }
  for (const b of buf) { if (b === 0) o = '1' + o; else break; }
  return o;
}
function sortKeys(o) {
  if (Array.isArray(o)) return o.map(sortKeys);
  if (o && typeof o === 'object') return Object.keys(o).sort().reduce((a, k) => { a[k] = sortKeys(o[k]); return a; }, {});
  return o;
}
export function jcs(o) { return Buffer.from(JSON.stringify(sortKeys(o)), 'utf8'); }
const sha = (b) => createHash('sha256').update(b).digest();

export const SCHEMA_V22 = 'https://observerprotocol.org/schemas/delegation/v2.2.json';

/** Generate an Ed25519 did:key identity. */
export function makeAgent() {
  const kp = generateKeyPairSync('ed25519');
  const pub = Buffer.from(kp.publicKey.export({ format: 'jwk' }).x, 'base64url');
  const did = 'did:key:z' + b58(Buffer.concat([Buffer.from([0xed, 0x01]), pub]));
  return { did, privateKey: kp.privateKey, vm: did + '#' + did.slice('did:key:'.length) };
}

/** Issue a signed delegation credential with an arbitrary actionScope +
 * tradingMandate (schema v2.2 vocabulary). */
export function issueVac({ issuerDid, issuerPriv, issuerVm, subjectDid, actionScope, tradingMandate, validUntil = '2027-01-01T00:00:00Z' }) {
  const doc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:x402-' + b58(sha(jcs({ subjectDid, actionScope, tradingMandate })).subarray(0, 8)),
    type: ['VerifiableCredential', 'ObserverDelegationCredential'],
    issuer: issuerDid,
    validFrom: '2026-06-01T00:00:00Z',
    validUntil,
    credentialSchema: { id: SCHEMA_V22, type: 'JsonSchema' },
    credentialSubject: {
      id: subjectDid,
      authorizationLevel: 'policy',
      authorizationConfig: { policy: { policy_id: 'x402', rail_preference: ['eip155:84532', 'lightning'] } },
      actionScope,
      delegationScope: { may_delegate_further: false },
      enforcementMode: 'pre_transaction_check',
      ...(tradingMandate ? { tradingMandate } : {}),
    },
  };
  const po = { '@context': doc['@context'], type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: '2026-07-01T00:00:00Z', verificationMethod: issuerVm, proofPurpose: 'assertionMethod' };
  const hashData = Buffer.concat([sha(jcs(po)), sha(jcs(doc))]);
  return { ...doc, proof: { ...po, proofValue: 'z' + b58(edSign(null, hashData, issuerPriv)) } };
}

/** A VerifierConfig (policy object) pinned to the given issuer did:key. */
export function policyConfig(issuerDid, agentDid, dir, credentialPath) {
  return {
    credentialPath,
    issuerDid,
    agentDid,
    schemaAllowlist: [SCHEMA_V22],
    revocation: { maxStalenessHours: 24, onUnreachable: 'cache-then-deny', fetchTimeoutMs: 1500 },
    didCache: { maxStalenessHours: 24 },
    cacheDir: join(dir, 'cache'),
    auditLog: join(dir, 'decisions.jsonl'),
    rails: {
      'eip155:84532': { rail: 'base-sepolia', currency: 'ETH', decimals: 18, family: 'evm' },
      lightning: { rail: 'lightning', currency: 'sat', decimals: 0, family: 'other' },
    },
    allowContractCalls: false,
  };
}

/** The standard fixture set. Written to `dir`, returned as {name -> path}. */
export function writeFixtures(dir) {
  mkdirSync(dir, { recursive: true });
  const principal = makeAgent();
  const agent = makeAgent();
  const issue = (over) => issueVac({ issuerDid: principal.did, issuerPriv: principal.privateKey, issuerVm: principal.vm, subjectDid: agent.did, ...over });

  const PAY_TO = '0x209693Bc6afc0C5328bA36FaF03C514EF312287C';
  const creds = {
    // Per-payment + same-asset velocity caps on the x402 rail.
    'cred-x402-valid': issue({
      actionScope: { allowed_rails: ['eip155:84532'] },
      tradingMandate: { unit: 'USDC', maxNotionalPerOrder: 5, counterparty: { allowList: [PAY_TO] }, velocity: { dailyVolumeCap: 8 } },
    }),
    // One 24h budget across Lightning + x402 (the G8 shape).
    'cred-cross-rail': issue({
      actionScope: { allowed_rails: ['eip155:84532', 'lightning'] },
      tradingMandate: { crossRailBudget: { amount: '5', currency: 'USD', window: 'P1D', rates: { USDC: '1', sat: '0.0005' } } },
    }),
    'cred-cross-rail-badwindow': issue({
      actionScope: { allowed_rails: ['eip155:84532'] },
      tradingMandate: { crossRailBudget: { amount: '5', currency: 'USD', window: 'P2D', rates: { USDC: '1' } } },
    }),
    'cred-cross-rail-norate': issue({
      actionScope: { allowed_rails: ['eip155:84532'] },
      tradingMandate: { crossRailBudget: { amount: '5', currency: 'USD', window: 'P1D', rates: { sat: '0.0005' } } },
    }),
    'cred-expired': issue({ actionScope: { allowed_rails: ['eip155:84532'] }, validUntil: '2026-06-15T00:00:00Z' }),
    'cred-unknown-tm-rule': issue({
      actionScope: { allowed_rails: ['eip155:84532'] },
      tradingMandate: { futureConstraint: { anything: true } },
    }),
    'cred-no-constraint': issue({ actionScope: {} }),
  };

  // Agent-self-issued: the agent signs its own mandate (signer-boundary DENY).
  creds['cred-agent-self-issued'] = issueVac({ issuerDid: agent.did, issuerPriv: agent.privateKey, issuerVm: agent.vm, subjectDid: agent.did, actionScope: { allowed_rails: ['eip155:84532'] } });

  // Tampered: flip the budget after signing.
  const tampered = JSON.parse(JSON.stringify(creds['cred-cross-rail']));
  tampered.credentialSubject.tradingMandate.crossRailBudget.amount = '500000';
  creds['cred-tampered'] = tampered;

  const paths = {};
  for (const [name, doc] of Object.entries(creds)) {
    const p = join(dir, name + '.json');
    writeFileSync(p, JSON.stringify(doc, null, 2));
    paths[name] = p;
  }
  writeFileSync(join(dir, 'ids.json'), JSON.stringify({ principal: principal.did, agent: agent.did, payTo: PAY_TO }, null, 2));
  return { paths, principal, agent, payTo: PAY_TO };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const here = dirname(fileURLToPath(import.meta.url));
  const out = join(here, 'out');
  writeFixtures(out);
  console.log('x402 fixtures written to', out);
}
