import { createConnection } from "net";

const DEFAULT_SOCKET = "/var/run/dstack.sock";

interface TlsKeyResponse {
  /** PEM-encoded private key. */
  key: string;
  /**
   * PEM-encoded RA-TLS certificate chain. The leaf is index 0; intermediates
   * (KMS-signed app cert, OS image cert, root CA) follow. The dstack guest
   * agent always returns this field — older releases also returned a single
   * concatenated ``cert`` field, which we tolerate for backward compatibility.
   */
  certificate_chain?: string[];
  /**
   * Legacy single-cert field. dstack guest-agent versions before mid-2024
   * returned this instead of ``certificate_chain``. Deprecated; new SDK
   * builds prefer ``certificate_chain`` when both are present.
   */
  cert?: string;
}

/**
 * Options for {@link getDstackClientCert}.
 *
 * The dstack guest agent's ``/GetTlsKey`` endpoint accepts these fields,
 * which control what kind of cert the agent issues:
 *
 * - ``usageRaTls``: include the TDX attestation extension. Required for
 *   mutual RA-TLS where the server checks the client's quote.
 * - ``usageServerAuth``: cert is valid for TLS server authentication.
 * - ``usageClientAuth``: cert is valid for TLS client authentication.
 *   Required for mutual RA-TLS where this process is the *client*.
 */
export interface DstackTlsKeyOptions {
  usageRaTls?: boolean;
  usageServerAuth?: boolean;
  usageClientAuth?: boolean;
  subject?: string;
  altNames?: string[];
}

/**
 * Result of {@link getDstackClientCert}.
 *
 * - ``key``: PEM-encoded private key (Buffer).
 * - ``cert``: leaf cert PEM (Buffer). Backwards-compatible with prior
 *   v0.2.x callers.
 * - ``certChainPem``: full chain joined with ``\n`` (string). New in
 *   v0.3.0; consume in the forwarder for mutual RA-TLS handshakes.
 */
export interface DstackClientCert {
  key: Buffer;
  cert: Buffer;
  certChainPem: string;
}

/**
 * Obtain a client RA-TLS certificate from the dstack guest agent.
 *
 * The returned certificate is self-signed and contains a TDX attestation
 * quote in the Phala RA-TLS X.509 extension, binding this CVM's identity
 * to the TLS connection.
 *
 * Only works when the caller is running inside a dstack CVM. When
 * DSTACK_SIMULATOR_ENDPOINT is set, delegates to the simulator instead.
 *
 * @throws if the guest agent socket is not available or returns an error.
 */
export async function getDstackClientCert(
  socketPath: string = DEFAULT_SOCKET,
  options: DstackTlsKeyOptions = {}
): Promise<DstackClientCert> {
  const simulatorEndpoint = process.env["DSTACK_SIMULATOR_ENDPOINT"];
  if (simulatorEndpoint) {
    return fetchFromSimulator(simulatorEndpoint, options);
  }
  return fetchFromSocket(socketPath, options);
}

function buildPayload(options: DstackTlsKeyOptions): string {
  const body: Record<string, unknown> = {
    subject: options.subject ?? "",
    usage_ra_tls: options.usageRaTls ?? false,
    usage_server_auth: options.usageServerAuth ?? true,
    usage_client_auth: options.usageClientAuth ?? false,
  };
  if (options.altNames && options.altNames.length > 0) {
    body["alt_names"] = options.altNames;
  }
  return JSON.stringify(body);
}

function normalizeResponse(parsed: TlsKeyResponse): DstackClientCert {
  // Prefer certificate_chain when present (current dstack release shape).
  // Fall back to ``cert`` for older simulator builds.
  const chain = parsed.certificate_chain;
  if (chain && chain.length > 0) {
    const joined = chain.join("\n").endsWith("\n")
      ? chain.join("\n")
      : `${chain.join("\n")}\n`;
    return {
      key: Buffer.from(parsed.key, "utf8"),
      cert: Buffer.from(chain[0] ?? "", "utf8"),
      certChainPem: joined,
    };
  }
  if (parsed.cert) {
    return {
      key: Buffer.from(parsed.key, "utf8"),
      cert: Buffer.from(parsed.cert, "utf8"),
      certChainPem: parsed.cert.endsWith("\n")
        ? parsed.cert
        : `${parsed.cert}\n`,
    };
  }
  throw new Error(
    "dstack guest agent: response missing certificate_chain and cert"
  );
}

async function fetchFromSocket(
  socketPath: string,
  options: DstackTlsKeyOptions
): Promise<DstackClientCert> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    const chunks: Buffer[] = [];

    socket.on("connect", () => {
      const body = buildPayload(options);
      socket.write(
        `POST /GetTlsKey HTTP/1.1\r\n` +
          `Host: localhost\r\n` +
          `Content-Type: application/json\r\n` +
          `Content-Length: ${Buffer.byteLength(body)}\r\n` +
          `Connection: close\r\n` +
          `\r\n` +
          body
      );
    });

    socket.on("data", (chunk: Buffer) => chunks.push(chunk));

    socket.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      const separator = raw.indexOf("\r\n\r\n");
      if (separator === -1) {
        return reject(new Error("dstack guest agent: malformed HTTP response"));
      }
      const jsonBody = raw.slice(separator + 4);
      try {
        const parsed = JSON.parse(jsonBody) as TlsKeyResponse;
        resolve(normalizeResponse(parsed));
      } catch (err) {
        reject(
          new Error(`dstack guest agent: failed to parse response: ${err}`)
        );
      }
    });

    socket.on("error", (err: Error) => {
      reject(
        new Error(
          `dstack guest agent socket error (${socketPath}): ${err.message}. ` +
            "Is this process running inside a dstack CVM?"
        )
      );
    });

    socket.setTimeout(60_000, () => {
      socket.destroy();
      reject(new Error("dstack guest agent: connection timed out after 60s"));
    });
  });
}

async function fetchFromSimulator(
  endpoint: string,
  options: DstackTlsKeyOptions
): Promise<DstackClientCert> {
  const res = await fetch(`${endpoint}/GetTlsKey`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: buildPayload(options),
    signal: AbortSignal.timeout(60_000),
  });
  if (!res.ok) {
    throw new Error(
      `dstack simulator GetTlsKey failed with status ${res.status}`
    );
  }
  const data = (await res.json()) as TlsKeyResponse;
  return normalizeResponse(data);
}
