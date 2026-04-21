export { withRaTls } from "./adapter.js";
export { withRaTlsManifest, resolveLeader } from "./connect-manifest.js";
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
