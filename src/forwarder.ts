/**
 * Local TCP forwarder that terminates RA-TLS on behalf of the postgres driver.
 *
 * Why this exists
 * ---------------
 *
 * The dstack gateway in TLS-passthrough mode routes by parsing the TLS
 * ClientHello's SNI to pick a target CVM, *before* forwarding raw bytes on.
 * Standard postgres clients (libpq, pg/node-postgres, sqlx, prisma) start
 * every ``sslmode=require`` connection with the postgres-specific
 * ``SSLRequest`` 8-byte plaintext preamble and wait for a single-byte reply
 * before sending the TLS ClientHello. The gateway sees the SSLRequest as
 * the first bytes, fails SNI extraction (first byte ``0x00`` is not the
 * TLS handshake record type ``0x16``), and closes the connection.
 *
 * We can't trust the customer's CVM absent the RA-TLS handshake itself, so
 * we can't give customers a raw sidecar endpoint that bypasses the gateway.
 * That rules out "node-postgres does its own TLS handshake" as the
 * data-plane path.
 *
 * The fix moves TLS out of node-postgres. This module runs a localhost
 * ``net.createServer`` TCP listener inside the client process; on every
 * accept it opens a *raw* TLS connection (no ``SSLRequest`` preamble) to
 * the cluster, presents the dstack-issued RA-TLS client certificate,
 * verifies the server's TDX quote via the caller's verifier, and then
 * bridges bytes bidirectionally between the accepted local stream and
 * the TLS-wrapped upstream stream.
 *
 * From node-postgres' perspective it's talking to a plain-TCP local
 * postgres server with ``sslmode=disable``. From the sidecar's
 * perspective it's getting a raw-TLS mutual-RA-TLS handshake with a
 * valid client cert. The gateway sees a well-formed TLS ClientHello in
 * the first bytes and routes happily.
 *
 * Trust model
 * -----------
 *
 * The local hop (pg ↔ forwarder ↔ TLS tunnel) lives inside the client
 * process — both ends are the same TEE CVM. The plaintext segment never
 * crosses a process boundary or an untrusted network. The actual
 * mutual-RA-TLS handshake happens on the upstream leg, exactly as the
 * trust model documents.
 *
 * Lifecycle
 * ---------
 *
 * ``RaTlsForwarder`` owns a single ``net.Server`` plus a per-accept
 * upstream ``tls.connect``. Calling ``stop()`` closes the listener and
 * ends in-flight bridges. For the common "one-pool-per-process"
 * ``connectViaManifest`` flow the forwarder is module-registered so
 * Node's GC doesn't collect it while node-postgres still has open
 * connections to the listener.
 */
import { createServer, type Server, type Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { extractTdxQuote } from "./cert.js";
import type { RaTlsVerifier, VerifyOptions } from "./types.js";

// Keep a reference to every started forwarder so the listener +
// in-flight bridges aren't GC'd while the postgres driver still has
// open connections to them.
const _FORWARDERS: RaTlsForwarder[] = [];

/** Options for {@link RaTlsForwarder}. */
export interface RaTlsForwarderOptions {
  /** Upstream sidecar host (the dstack gateway-rewritten host). */
  targetHost: string;
  /** Upstream sidecar port. */
  targetPort: number;
  /**
   * Concatenated PEM cert chain presented during the upstream
   * mutual-RA-TLS handshake. Comes from the dstack guest agent's
   * ``GetTlsKey`` (chain joined with ``\n``).
   */
  clientCertChainPem: string;
  /** PEM-encoded private key matching the leaf of ``clientCertChainPem``. */
  clientKeyPem: string;
  /** Verifier applied to the server's TDX quote on every upstream handshake. */
  verifier: RaTlsVerifier;
  /** Verifier options (allowed MRTD list, debug-mode flag). */
  verifyOptions?: VerifyOptions;
  /**
   * If ``true``, accept upstream certs that have no TDX attestation
   * extension (e.g. plain Postgres or simulator).
   *
   * Default: ``false``.
   */
  allowSimulator?: boolean;
}

/** Per-connection timeout for upstream TLS handshake / TCP connect. */
const UPSTREAM_HANDSHAKE_TIMEOUT_MS = 15_000;

/**
 * Background localhost forwarder that terminates mutual RA-TLS for a
 * Prisma / node-postgres client.
 *
 * The forwarder binds to ``127.0.0.1:0`` (random ephemeral port). Every
 * accepted local connection triggers a fresh TLS handshake to the
 * configured upstream, presenting the dstack-issued client cert and
 * verifying the server's TDX quote before any postgres bytes flow.
 */
export class RaTlsForwarder {
  private server: Server | null = null;
  private boundPort: number | null = null;
  private readonly bridges: Set<{ local: Socket; upstream: TLSSocket }> =
    new Set();

  constructor(private readonly options: RaTlsForwarderOptions) {}

  /**
   * Start the listener. Resolves once the listener is bound; the
   * returned promise yields the local ``127.0.0.1:<port>`` address.
   */
  start(): Promise<{ host: string; port: number }> {
    return new Promise((resolve, reject) => {
      const server = createServer((local) => this.handleAccept(local));
      server.on("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        if (addr === null || typeof addr === "string") {
          reject(new Error("forwarder: unexpected listener address"));
          return;
        }
        this.server = server;
        this.boundPort = addr.port;
        resolve({ host: "127.0.0.1", port: addr.port });
      });
    });
  }

  /**
   * Local listener address. Throws if {@link start} hasn't returned yet.
   */
  get localAddr(): { host: string; port: number } {
    if (this.boundPort === null) {
      throw new Error("RaTlsForwarder: start() has not been called");
    }
    return { host: "127.0.0.1", port: this.boundPort };
  }

  /**
   * Stop accepting new connections and tear down in-flight bridges.
   * Idempotent.
   */
  async stop(): Promise<void> {
    const server = this.server;
    this.server = null;
    if (server === null) return;
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
    for (const bridge of this.bridges) {
      bridge.local.destroy();
      bridge.upstream.destroy();
    }
    this.bridges.clear();
  }

  private handleAccept(local: Socket): void {
    // Errors on the local socket pre-upstream-connect: drop quietly.
    local.on("error", () => {
      /* graceful pool close surfaces here as ECONNRESET; ignore */
    });

    this.openUpstreamAndBridge(local).catch((err) => {
      // Surface unexpected forwarder failures to stderr; node-postgres
      // will see the dropped connection and propagate as a connection
      // error to the caller.
      // eslint-disable-next-line no-console
      console.warn(
        `prisma-ra-tls forwarder: upstream connection failed: ${
          err instanceof Error ? err.message : String(err)
        }`
      );
      try {
        local.destroy();
      } catch {
        /* ignore */
      }
    });
  }

  private async openUpstreamAndBridge(local: Socket): Promise<void> {
    const upstream = await this.connectUpstream();
    const bridge = { local, upstream };
    this.bridges.add(bridge);

    const cleanup = (): void => {
      this.bridges.delete(bridge);
      try {
        local.destroy();
      } catch {
        /* ignore */
      }
      try {
        upstream.destroy();
      } catch {
        /* ignore */
      }
    };

    upstream.on("error", cleanup);
    local.on("close", cleanup);
    upstream.on("close", cleanup);

    // Bridge bytes both ways. ``pipe`` handles backpressure for us.
    local.pipe(upstream);
    upstream.pipe(local);
  }

  private connectUpstream(): Promise<TLSSocket> {
    return new Promise<TLSSocket>((resolve, reject) => {
      const socket = tlsConnect({
        host: this.options.targetHost,
        port: this.options.targetPort,
        servername: this.options.targetHost,
        key: this.options.clientKeyPem,
        cert: this.options.clientCertChainPem,
        // RA-TLS server certs are self-signed; trust derives from the
        // embedded TDX quote, not PKI. We run the verifier ourselves
        // post-handshake, so disable Node's chain + hostname checks.
        rejectUnauthorized: false,
      });

      const timer = setTimeout(() => {
        try {
          socket.destroy();
        } catch {
          /* ignore */
        }
        reject(
          new Error(
            `upstream TLS handshake timed out after ${UPSTREAM_HANDSHAKE_TIMEOUT_MS}ms`
          )
        );
      }, UPSTREAM_HANDSHAKE_TIMEOUT_MS);

      socket.once("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });

      socket.once("secureConnect", () => {
        clearTimeout(timer);
        this.verifyUpstream(socket).then(
          () => resolve(socket),
          (err: Error) => {
            try {
              socket.destroy();
            } catch {
              /* ignore */
            }
            reject(err);
          }
        );
      });
    });
  }

  private async verifyUpstream(socket: TLSSocket): Promise<void> {
    const peerCert = socket.getPeerCertificate(true);
    if (!peerCert?.raw) {
      throw new Error("upstream presented no leaf certificate");
    }
    const derCert = Buffer.from(peerCert.raw);
    const quote = extractTdxQuote(derCert);
    if (quote === null) {
      if (this.options.allowSimulator) {
        // eslint-disable-next-line no-console
        console.warn(
          "prisma-ra-tls forwarder: upstream cert has no TDX attestation extension; " +
            "continuing because allowSimulator=true"
        );
        return;
      }
      throw new Error(
        "upstream cert has no TDX attestation extension; " +
          "set allowSimulator: true for non-TEE targets"
      );
    }
    await this.options.verifier.verify(
      quote,
      this.options.verifyOptions ?? {}
    );
  }
}

/**
 * Module-level registry that keeps started forwarders alive for the
 * lifetime of the process. Used by {@link connectViaManifest} so
 * callers don't have to manage lifecycles by hand.
 *
 * Exposed for tests; callers that want explicit lifecycle control
 * should hold their own ``RaTlsForwarder`` and call ``stop()`` directly.
 */
export function registerForwarder(forwarder: RaTlsForwarder): void {
  _FORWARDERS.push(forwarder);
}

/** Currently-alive forwarders held by this module. Test-only helper. */
export function registeredForwarders(): RaTlsForwarder[] {
  return [..._FORWARDERS];
}
