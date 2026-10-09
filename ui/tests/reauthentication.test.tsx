import { afterEach, describe, expect, it, vi } from "vitest";
import {
  handleReauthenticationRequired,
  setOnReauthenticationRequired,
} from "../src/auth/hooks";

/** The 403 the auth server answers for a change needing a recent login. */
const REFUSED = {
  status: 403,
  result: { error: "Reauthentication required: log in again to continue" },
};

afterEach(() => {
  setOnReauthenticationRequired(() => {});
});

describe("handleReauthenticationRequired", () => {
  it("runs the reauthentication handler for a refused change", () => {
    const handler = vi.fn();
    setOnReauthenticationRequired(handler);
    expect(handleReauthenticationRequired(REFUSED)).toBe(true);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("leaves other errors to the caller", () => {
    const handler = vi.fn();
    setOnReauthenticationRequired(handler);
    expect(
      handleReauthenticationRequired({
        status: 403,
        result: { error: "Permission denied" },
      }),
    ).toBe(false);
    expect(handleReauthenticationRequired(new Error("network"))).toBe(false);
    expect(handleReauthenticationRequired(undefined)).toBe(false);
    expect(handler).not.toHaveBeenCalled();
  });
});
