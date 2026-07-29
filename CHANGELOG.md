# Changelog

All notable changes to `@observer-protocol/x402-op-authorize`.

## 0.3.0

### Security

- Rebuilt against `@observer-protocol/policy-engine` 0.4.0, which closes a
  credential-controlled URL dereference. `credentialStatus[].statusListCredential` is chosen
  by whoever signs the credential and was fetched with `redirect: 'follow'` and no validation:
  no scheme check, no address-class check, no per-hop redirect check. The issuer check that
  catches a hostile status list reads the response body, so it could reject what came back and
  could not prevent the request.

  **This package bundles the engine at build time, so the fix does not reach you through an
  engine version bump. It arrives only in this release.**

  Now: a status-list URL is dereferenced only when same-origin with a `did:web` issuer or
  listed in `config.statusListOriginAllowlist` (empty by default); every outbound dereference
  is scheme-checked and address-class-checked as literals and as DNS answers, redirects are
  followed manually and re-validated per hop, and https-to-http downgrade refuses. `did:web`
  resolution is https-only; the plain-http loopback affordance is gone.

  Known residual, stated rather than omitted: DNS rebinding is not closed. The guard resolves
  and validates, then `fetch` resolves again. Closing it needs a connection-pinned dispatcher
  and therefore a runtime dependency the engine deliberately does not have.

### Changed, behaviour

- **Denial tags: a property the published schemas accept but no engine enforces now denies as
  `[unenforceable]` rather than `[unknown-rule]`.** Same verdict as before, different stated
  cause. **If you parse denial reason strings, this changes what you see** for
  `actionScope.allowed_counterparty_types` and `spending_limits.per_asset`. Everything else is
  unchanged. The distinction exists because reporting a schema-valid field as unrecognized told
  an issuer nothing about why their credential was refused.

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
