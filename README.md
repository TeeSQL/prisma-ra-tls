# prisma-ra-tls

A [Prisma driver adapter](https://www.prisma.io/docs/orm/overview/databases/database-drivers) that verifies **TDX attestation** before allowing any queries through to a Postgres database running inside a Trusted Execution Environment (TEE).

Built for databases hosted on [dstack](https://github.com/Dstack-TEE/dstack) (Intel TDX). Works with any RA-TLS secured Postgres instance that embeds a TDX quote in the server's X.509 certificate using the [Phala RA-TLS extensions](https://github.com/Dstack-TEE/dstack/tree/master/ra-tls).

## What it does

When your application connects to the database, `prisma-ra-tls`:

1. Completes the TLS handshake (the server presents a self-signed RA-TLS certificate)
2. Extracts the TDX attestation quote from the certificate's X.509 extension
3. Submits the quote to [Intel Trust Authority](https://portal.trustauthority.intel.com) for verification
4. Validates the response: debug mode off, TCB status acceptable, MRTD in allowlist (if configured)
5. Caches the result for subsequent connections (default: 1 hour)
6. Only then allows queries through

If verification fails at any step, the connection is refused and an error is thrown.

## Installation

```bash
npm install prisma-ra-tls
# peer dependencies
npm install pg @prisma/adapter-pg
```

Requires Node.js ≥ 18, Prisma ≥ 5.10.

## Setup

### 1. Enable driver adapters in your Prisma schema

```prisma
generator client {
  provider        = "prisma-client-js"
  previewFeatures = ["driverAdapters"]
}
```

### 2. Get an Intel Trust Authority API key

Register at [portal.trustauthority.intel.com](https://portal.trustauthority.intel.com). The service is free.

### 3. Use the adapter

```ts
import { PrismaClient } from "@prisma/client"
import { withRaTls, IntelApiVerifier } from "prisma-ra-tls"

const adapter = await withRaTls(process.env.DATABASE_URL!, {
  verifier: new IntelApiVerifier(),
  // Optional: pin the expected TD measurement (hex, from your CVM image build)
  allowedMrTd: [process.env.EXPECTED_MRTD],
})

export const prisma = new PrismaClient({ adapter })
```

Set the environment variable:

```bash
INTEL_TRUST_AUTHORITY_API_KEY=your-api-key
DATABASE_URL=postgres://postgres@your-cluster.phala.network:5433/postgres
```

## Options

```ts
withRaTls(connectionString, {
  // Required: verifier implementation
  verifier: new IntelApiVerifier(),

  // Optional: pin expected MRTD values (hex strings, with or without 0x prefix)
  // If omitted, any MRTD is accepted — not recommended for production
  allowedMrTd: ["0abc123..."],

  // Allow debug TDs (tdx_is_debuggable=true). Default: false
  // Debug TDs have no confidentiality guarantees. Never enable in production.
  allowDebugMode: false,

  // Allow connections to servers with no TDX quote in their certificate.
  // Required when pointing at a dstack simulator or a plain Postgres instance.
  // Default: false
  allowSimulator: false,

  // Present a client RA-TLS certificate (mutual RA-TLS).
  // Requires this application to be running inside a dstack CVM.
  // Default: false
  clientAttestation: false,

  // dstack guest agent socket path. Only used when clientAttestation: true.
  // Default: /var/run/dstack.sock
  dstackSocket: "/var/run/dstack.sock",

  // Cert verification cache TTL in milliseconds. Default: 3600000 (1 hour)
  cacheTtlMs: 3_600_000,

  // Prisma schema override
  schema: "public",
})
```

## Modes

### Server-only attestation (default)

The client can run anywhere. It verifies the *database* is a legitimate, unmodified TEE before trusting it with credentials and queries.

```ts
const adapter = await withRaTls(url, {
  verifier: new IntelApiVerifier(),
  allowedMrTd: [process.env.EXPECTED_MRTD],
})
```

### Mutual RA-TLS

Both sides attest to each other. The application must also be running inside a dstack CVM. The database server verifies the client's attestation certificate and rejects connections from non-TEE clients.

```ts
const adapter = await withRaTls(url, {
  verifier: new IntelApiVerifier(),
  clientAttestation: true,  // calls /var/run/dstack.sock to get a client cert
})
```

### Simulator / development

```ts
import { withRaTls, NoopVerifier } from "prisma-ra-tls"

const adapter = await withRaTls(url, {
  verifier: new NoopVerifier(),  // skips all attestation checks
  allowSimulator: true,
})
```

Or detect automatically:

```ts
const isDev = !!process.env.DSTACK_SIMULATOR_ENDPOINT

const adapter = await withRaTls(url, {
  verifier: isDev ? new NoopVerifier() : new IntelApiVerifier(),
  allowSimulator: isDev,
})
```

## Custom verifier

Implement the `RaTlsVerifier` interface to use a different attestation backend (e.g. a local DCAP verification service, AMD SEV attestation, or a caching proxy in front of Intel Trust Authority):

```ts
import type { RaTlsVerifier, VerificationResult, VerifyOptions } from "prisma-ra-tls"

class MyVerifier implements RaTlsVerifier {
  async verify(quote: Buffer, options: VerifyOptions): Promise<VerificationResult> {
    // quote is the raw TDX quote bytes extracted from the RA-TLS cert
    const result = await myAttestationService.verify(quote)
    return {
      mrTd: result.tdMeasurement,
      rtmr0: result.rtmr0,
      rtmr1: result.rtmr1,
      rtmr2: result.rtmr2,
      rtmr3: result.rtmr3,
      tcbStatus: result.tcbStatus,
      isDebugMode: result.debugMode,
    }
  }
}
```

## How RA-TLS works

In a standard TLS handshake, the server's certificate is signed by a trusted CA. In RA-TLS, the server generates a **self-signed** certificate, but embeds a hardware attestation quote in a custom X.509 extension. The quote proves:

- The server is running inside a genuine Intel TDX Trusted Domain
- The TD's measurements (MRTD, RTMRs) match the expected software stack
- The platform's TCB (firmware + microcode) is up to date

The TLS public key is bound to the quote via the `REPORTDATA` field, preventing a man-in-the-middle from substituting their own certificate.

`prisma-ra-tls` parses the [Phala RA-TLS extensions](https://github.com/Dstack-TEE/dstack/blob/master/ra-tls/src/oids.rs) (OID `1.3.6.1.4.1.62397.1.1`) and delegates quote verification to Intel Trust Authority.

## Security considerations

- **Always pin `allowedMrTd`** in production. Without it, any legitimate TDX CVM running any code is accepted.
- **Never set `allowDebugMode: true`** in production. Debug TDs can be inspected and have no confidentiality.
- **`allowSimulator: true`** disables all attestation. Never use in production.
- The attestation cache (default 1 hour) means a compromised CVM could remain connected for up to `cacheTtlMs` after its TCB status changes. Tune accordingly.
- Intel Trust Authority is a third-party service. Attestation failures will prevent new connections from being established. Plan for retries and connection pool warmup.

## Roadmap

- [ ] v1.1: Full SCALE decode for `PHALA_RATLS_ATTESTATION` OID (`1.3.6.1.4.1.62397.1.8`)
- [ ] v1.2: Local DCAP binary verifier (air-gapped deployments)
- [ ] v1.3: Event log (RTMR replay) verification
- [ ] v2.0: AMD SEV-SNP support

## License

Apache 2.0 — see [LICENSE](LICENSE).

The Apache 2.0 license was chosen because the TEE/attestation space involves patents held by Intel and others. Apache 2.0 includes an explicit patent grant, protecting users of this library.
