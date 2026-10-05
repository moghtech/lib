import type * as Types from "./types.ts";

/** The responses of `/supporter/read`, by request. */
export type SupporterReadResponses = {
  /** `null` without a key. */
  GetSupporterKey: Types.SignedSupporterKey | null;
  GetSupporterKeyInfo: Types.GetSupporterKeyInfoResponse;
  GetSupporterBranding: Types.GetSupporterBrandingResponse;
};

/** The responses of `/supporter/write`, by request. */
export type SupporterWriteResponses = {
  SetSupporterKey: Types.SetSupporterKeyResponse;
  DeleteSupporterKey: Types.DeleteSupporterKeyResponse;
  SetSupporterBranding: Types.SetSupporterBrandingResponse;
};
