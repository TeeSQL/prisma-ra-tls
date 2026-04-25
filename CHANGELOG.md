# prisma-ra-tls Changelog

## 0.3.0

### What changed

Mutual RA-TLS now flows through an in-process localhost forwarder.
The dstack gateway routes by SNI parsed from the first bytes of the
connection, but node-postgres opens every `sslmode=require` connection
with the postgres `SSLRequest` 8-byte preamble — first byte `0x00` is
not the TLS handshake record type `0x16`, so the gateway tears the
connection down before the ClientHello arrives. v0.3.0 moves TLS out
of node-postgres: the SDK starts a localhost listener inside the
client process, terminates mutual RA-TLS against the cluster's sidecar
on every accept, and hands node-postgres a plain-TCP local DSN with
`sslmode=disable`.

This matches the v0.3.0 design we shipped in `sqlx-ra-tls` (Rust) and
`psycopg-ra-tls` (Python).

### Added

- `RaTlsForwarder` in `forwarder.ts`: per-connection mutual-RA-TLS
  termination over a `127.0.0.1:<ephemeral>` listener. Uses the
  TDX-attested client cert from the dstack guest agent on every
  upstream handshake.
- `connectViaManifest()` in `connect-manifest.ts`: discovers the
  current leader via signed DNS TXT manifest, starts a forwarder, and
  returns a localhost DSN you can hand directly to `PrismaPg`.
- `openLocalForwarder()` and `rewriteDsnToForwarder()` in `connect.ts`
  for callers who want to drive the forwarder lifecycle by hand.
- `getDstackClientCert()` now returns the full PEM certificate chain
  (`certChainPem` field), needed for mutual-RA-TLS handshakes against
  sidecars that verify intermediate certs.

### Changed (breaking-on-internal-shape, source-compatible for
public API)

- `getDstackClientCert()`'s response shape is now
  `{ key, cert, certChainPem }`. The old `{ key, cert }` shape is
  still produced (the `cert` field still holds the leaf), so direct
  destructuring callers continue to work.
- `withRaTls()` and `withRaTlsManifest()` continue to work as in v0.2,
  but `withRaTlsManifest()` is now backed by the same forwarder as
  `connectViaManifest()`. Existing callers see no behavior change at
  the call site; the underlying TLS termination location moves.

### Deprecated

- `withRaTlsManifest()` — prefer `connectViaManifest()`. The old name
  remains as a thin wrapper that builds a `PrismaPg` adapter from the
  forwarder's local DSN. Will be removed in v1.0.

### Trust-anchor caveat (TODO)

- The forwarder verifies the upstream server's TDX quote via the
  caller-supplied `RaTlsVerifier`. There is no JS DCAP verifier yet;
  for now the manifest-signer is the trust anchor (signs the leader
  URL via DNS TXT) and `NoopVerifier` is the recommended pairing for
  operator-side scripts. A first-class JS DCAP verifier is tracked in
  the platform-wide migration plan
  `docs/plans/mutual-ra-tls-dcap-migration.md` (Phase 3 mirrors what's
  shipping for sqlx-ra-tls in Phase 1–2).

## 0.2.0

- DNS TXT manifest discovery for endpoint-registry v2.

## 0.1.0

- Initial release: TDX attestation verification for prisma + node-postgres.
