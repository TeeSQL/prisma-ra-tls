// `@peculiar/x509` (transitively, `tsyringe`) requires the
// `reflect-metadata` polyfill be loaded once before any of its modules
// initialise. We import it here so consumers get a ready-to-use
// package without having to add the polyfill to their entry point.
import "reflect-metadata";

export { withRaTls } from "./adapter.js";
export {
  connectViaManifest,
  resolveLeader,
  withRaTlsManifest,
  type ConnectViaManifestOptions,
  type ManifestConnection,
} from "./connect-manifest.js";
export {
  openLocalForwarder,
  rewriteDsnToForwarder,
  type OpenForwarderOptions,
} from "./connect.js";
export {
  RaTlsForwarder,
  registerForwarder,
  registeredForwarders,
  type RaTlsForwarderOptions,
} from "./forwarder.js";
export {
  type Manifest,
  ManifestError,
  canonicalBody,
  parseAndVerify,
  MANIFEST_VERSION,
} from "./manifest.js";
export {
  buildRecordName,
  postgresHostFromLeaderUrl,
  queryManifestTxt,
} from "./discovery.js";
export { IntelApiVerifier } from "./verifiers/intel.js";
export type { IntelApiVerifierOptions } from "./verifiers/intel.js";
export { NoopVerifier } from "./verifiers/noop.js";
export type {
  RaTlsOptions,
  RaTlsVerifier,
  VerificationResult,
  VerifyOptions,
} from "./types.js";
