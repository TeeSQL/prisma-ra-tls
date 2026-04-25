/**
 * Forwarder-based RA-TLS connect entrypoint for prisma-ra-tls v0.3.0.
 *
 * The dstack gateway in TLS-passthrough mode routes by SNI parsed from
 * the very first bytes of the connection. node-postgres opens every
 * ``sslmode=require`` connection with the postgres ``SSLRequest`` frame
 * (8 bytes ``[00 00 00 08 04 D2 16 2F]``), which the gateway can't
 * recognize as a TLS ClientHello — first byte ``0x00`` ≠ TLS handshake
 * record type ``0x16`` — so it tears down the connection.
 *
 * The mitigation: this module starts an in-process localhost
 * {@link RaTlsForwarder}, which terminates mutual RA-TLS against the
 * cluster and bridges bytes. The caller hands node-postgres a localhost
 * DSN with ``sslmode=disable``; node-postgres has no idea TLS is even
 * involved.
 *
 * See ``docs/architecture/trust-model.md`` for the full trust analysis.
 */
import { RaTlsForwarder, registerForwarder } from "./forwarder.js";
import { getDstackClientCert } from "./dstack.js";
import type { RaTlsVerifier, VerifyOptions } from "./types.js";

/** Placeholder password sent to the proxy when the DSN contains no password.
 *
 * The sidecar proxy discards whatever password the client sends and
 * substitutes the KMS-derived password before forwarding to Postgres,
 * so the actual value here never leaves the client.
 */
const RATLS_PLACEHOLDER_PASSWORD = "ratls";

/** Options for {@link openLocalForwarder}. */
export interface OpenForwarderOptions {
  /** Verifier applied to the upstream server's TDX quote. */
  verifier: RaTlsVerifier;
  /** Verifier options (allowed MRTD list, debug-mode flag). */
  verifyOptions?: VerifyOptions;
  /**
   * Accept upstream certs that have no TDX attestation extension.
   * Required when pointing at a dstack simulator or a non-TEE
   * postgres. Default: ``false``.
   */
  allowSimulator?: boolean;
  /**
   * Override the dstack guest agent socket path. Default:
   * ``/var/run/dstack.sock``.
   */
  dstackSocket?: string;
}

/**
 * Start an RA-TLS forwarder bound to ``127.0.0.1:<ephemeral>`` that
 * terminates mutual RA-TLS against the given target on every accept.
 *
 * The forwarder is module-registered so Node's GC doesn't collect it
 * while node-postgres still has open connections to the local listener.
 */
export async function openLocalForwarder(
  targetHost: string,
  targetPort: number,
  options: OpenForwarderOptions
): Promise<RaTlsForwarder> {
  const { key, certChainPem } = await getDstackClientCert(
    options.dstackSocket,
    {
      usageRaTls: true,
      usageServerAuth: true,
      usageClientAuth: true,
    }
  );

  const forwarder = new RaTlsForwarder({
    targetHost,
    targetPort,
    clientCertChainPem: certChainPem,
    clientKeyPem: key.toString("utf8"),
    verifier: options.verifier,
    verifyOptions: options.verifyOptions,
    allowSimulator: options.allowSimulator ?? false,
  });
  await forwarder.start();
  registerForwarder(forwarder);
  return forwarder;
}

/**
 * Rewrite a URL DSN's host/port to the forwarder's local address and
 * force ``sslmode=disable``.
 *
 * The forwarder terminates TLS against the cluster; by the time the
 * postgres wire protocol flows, we're talking plain TCP across
 * loopback. ``sslmode=disable`` avoids node-postgres attempting its
 * own TLS upgrade on top.
 */
export function rewriteDsnToForwarder(
  dsn: string,
  localHost: string,
  localPort: number
): string {
  if (!(dsn.startsWith("postgresql://") || dsn.startsWith("postgres://"))) {
    throw new Error(
      "prisma-ra-tls v0.3 requires a URI-form DSN (postgresql://user:pw@host:port/db)"
    );
  }
  const parsed = new URL(dsn);

  // Normalise userinfo. The sidecar requires teesql_read /
  // teesql_readwrite on the wire but the password is substituted with
  // the KMS-derived credential, so we only need *something* in the
  // password slot for the parser.
  const username = parsed.username;
  const password = parsed.password || RATLS_PLACEHOLDER_PASSWORD;

  parsed.username = username;
  parsed.password = password;
  parsed.hostname = localHost;
  parsed.port = String(localPort);

  // Force sslmode=disable, replacing any caller-supplied sslmode.
  parsed.searchParams.delete("sslmode");
  parsed.searchParams.set("sslmode", "disable");

  return parsed.toString();
}

/**
 * Parse a URL-form DSN and return ``(host, port)``. Throws when the DSN
 * is missing a host or isn't URL-form.
 *
 * @internal exported for testing
 */
export function parseDsnTarget(dsn: string): { host: string; port: number } {
  if (!(dsn.startsWith("postgresql://") || dsn.startsWith("postgres://"))) {
    throw new Error(
      "prisma-ra-tls v0.3 requires a URI-form DSN (postgresql://user:pw@host:port/db)"
    );
  }
  const parsed = new URL(dsn);
  if (!parsed.hostname) throw new Error("DSN has no host");
  const port = parsed.port ? Number(parsed.port) : 5432;
  return { host: parsed.hostname, port };
}
