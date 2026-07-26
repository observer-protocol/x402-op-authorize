# Changelog

All notable changes to `@observer-protocol/x402-op-authorize`.

## 0.2.3

### Changed — metadata honesty (no code changes)

- npm description no longer names the Cloudflare Monetization Gateway, a product this
  package has never exchanged a byte with; keywords `cloudflare` and
  `monetization-gateway` removed.
- "Cloudflare Agents SDK payments" removed from the composable-client lists in README,
  source comments, and SCOPE §2: asserted but never live-fired. Its expected-but-untested
  status is recorded in SCOPE §2; SUPPORT-MATRIX remains the list of what has been fired.

## 0.2.0

### Changed — inherits fail-closed core (behavior narrowing)

- Bundles `@observer-protocol/policy-engine` 0.3.0, which is **fail-closed by default**:
  a delegation credential with an unrecognized mandate shape is now **denied** where
  earlier versions allowed it. This narrowing is inherited via the embedded core. **If
  you relied on the prior fail-open behavior, you were relying on a bug.**

### Added

- `https://observerprotocol.org/schemas/delegation/v2.4.json` added to the documented
  example `schemaAllowlist` — the current Sovereign-issued delegation schema — with a
  conformance case proving a v2.4 credential is verified and enforced end-to-end.
