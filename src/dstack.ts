import { createConnection } from "net";

const DEFAULT_SOCKET = "/var/run/dstack.sock";

interface TlsKeyResponse {
  key: string; // PEM-encoded private key
  cert: string; // PEM-encoded RA-TLS certificate (contains TDX quote)
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
  socketPath: string = DEFAULT_SOCKET
): Promise<{ key: Buffer; cert: Buffer }> {
  const simulatorEndpoint = process.env["DSTACK_SIMULATOR_ENDPOINT"];
  if (simulatorEndpoint) {
    return fetchFromSimulator(simulatorEndpoint);
  }
  return fetchFromSocket(socketPath);
}

async function fetchFromSocket(
  socketPath: string
): Promise<{ key: Buffer; cert: Buffer }> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    const chunks: Buffer[] = [];

    socket.on("connect", () => {
      // Minimal HTTP/1.1 request over Unix domain socket
      const body = "{}";
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
      // Split HTTP headers from body
      const separator = raw.indexOf("\r\n\r\n");
      if (separator === -1) {
        return reject(new Error("dstack guest agent: malformed HTTP response"));
      }
      const jsonBody = raw.slice(separator + 4);
      try {
        const parsed = JSON.parse(jsonBody) as TlsKeyResponse;
        resolve({
          key: Buffer.from(parsed.key, "utf8"),
          cert: Buffer.from(parsed.cert, "utf8"),
        });
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

    socket.setTimeout(5_000, () => {
      socket.destroy();
      reject(new Error("dstack guest agent: connection timed out after 5s"));
    });
  });
}

async function fetchFromSimulator(
  endpoint: string
): Promise<{ key: Buffer; cert: Buffer }> {
  const res = await fetch(`${endpoint}/GetTlsKey`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
    signal: AbortSignal.timeout(5_000),
  });
  if (!res.ok) {
    throw new Error(
      `dstack simulator GetTlsKey failed with status ${res.status}`
    );
  }
  const data = (await res.json()) as TlsKeyResponse;
  return {
    key: Buffer.from(data.key, "utf8"),
    cert: Buffer.from(data.cert, "utf8"),
  };
}
