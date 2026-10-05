// The key the platform's minting code produced with a test root key,
// the same fixture as `mogh_supporter::fixture` of the Rust crate.
// Never embed ROOT in a release.

import type { SignedSupporterKey } from "../src/index.ts";

export const ROOT_KID = "fe812c12f3ab4ce6";
export const ROOT_SPKI =
  "MCowBQYDK2VwAyEA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=";
export const ROOT_KEYS = [ROOT_SPKI];

export const APP = "komodo";

export const KEY =
  "qGF2AWFrSP6BLBLzq0zmYWlQAZCjwntqfMKx8EpdnjyPIWFhZmtvbW9kb2FuaUFjbWUgQ29ycGF0bG9yZ2FuaXphdGlvbmFzajIwMjUtMDEtMTVhY2oyMDI3LTA5LTMw.B569urTvMsFeTldR8Cmt9cnCY7SB81t_cG4-53VueFqF51BOmrAmoYk1o0toBHlUe0Z0WBpN2sGDEri4TVCwCA.NUVlvQ9tLCimq2RpjTvrr9t44m-zUjHDDVk5nymZQQw";

export const PAYLOAD_HEX =
  "a8617601616b48fe812c12f3ab4ce66169500190a3c27b6a7cc2b1f04a5d9e3c8f216161666b6f6d6f646f616e6941636d6520436f727061746c6f7267616e697a6174696f6e61736a323032352d30312d313561636a323032372d30392d3330";

/** 32 bytes all `0x01`. */
export const NONCE = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
export const NONCE_BYTES = new Uint8Array(32).fill(1);

/** What a correct `komodo` server answers for NONCE. */
export const RESPONSE: SignedSupporterKey = {
  payload:
    "qGF2AWFrSP6BLBLzq0zmYWlQAZCjwntqfMKx8EpdnjyPIWFhZmtvbW9kb2FuaUFjbWUgQ29ycGF0bG9yZ2FuaXphdGlvbmFzajIwMjUtMDEtMTVhY2oyMDI3LTA5LTMw",
  payload_sig:
    "B569urTvMsFeTldR8Cmt9cnCY7SB81t_cG4-53VueFqF51BOmrAmoYk1o0toBHlUe0Z0WBpN2sGDEri4TVCwCA",
  instance_public_key: "tU_ASxS6_yGAysVMYx0NGCR6Swuntgu-uby1IaODjK8",
  nonce_sig:
    "_hTfDp5rVtAtRhe2i8vM7Hx3kLYN8ks4TnW4b5MjIsB1zLJwiKjEc1ENRo7q_nKN9utZXP12WNqGxVuVTLzQCg",
};

export const ID = "0190a3c2-7b6a-7cc2-b1f0-4a5d9e3c8f21";
export const NAME = "Acme Corp";
export const TIER = "organization";
export const SINCE = "2025-01-15";
export const COVERS = "2027-09-30";

export const SUPPORTER = {
  version: 1,
  rootKeyId: ROOT_KID,
  id: ID,
  app: APP,
  name: NAME,
  tier: TIER,
  since: SINCE,
  covers: COVERS,
};

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
