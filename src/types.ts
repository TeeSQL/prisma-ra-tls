export interface VerifyOptions {
  /** Allowlist of acceptable MRTD values (hex strings). If empty, any MRTD is accepted. */
  allowedMrTd?: string[];
  /** Allow connections where tdx_is_debuggable=true. Default: false */
  allowDebugMode?: boolean;
}

export interface VerificationResult {
  mrTd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  tcbStatus: string;
  isDebugMode: boolean;
}

export interface RaTlsVerifier {
  verify(quote: Buffer, options: VerifyOptions): Promise<VerificationResult>;
}

export interface RaTlsOptions extends VerifyOptions {
  /** Attestation verifier. Use IntelApiVerifier for production, NoopVerifier for tests. */
  verifier: RaTlsVerifier;
  /**
   * Allow connections where the server cert has no TDX quote embedded.
   * Required when connecting to a non-TEE server (e.g. dstack simulator).
   * Default: false
   */
  allowSimulator?: boolean;
  /**
   * Present a client RA-TLS certificate (mutual RA-TLS).
   * Requires the application to be running inside a dstack CVM.
   * Default: false
   */
  clientAttestation?: boolean;
  /**
   * Path to the dstack guest agent Unix socket.
   * Only used when clientAttestation is true.
   * Default: /var/run/dstack.sock
   */
  dstackSocket?: string;
  /**
   * How long to cache a successful verification for a given cert (ms).
   * Intel Trust Authority attestation tokens are valid for several hours.
   * Default: 3600000 (1 hour)
   */
  cacheTtlMs?: number;
  /** Prisma schema override. Passed through to PrismaPg. */
  schema?: string;
}
