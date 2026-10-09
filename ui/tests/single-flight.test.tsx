import { act, renderHook, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { setAuthUrl } from "../src/auth/hooks";
import { EnrollPasskey } from "../src/auth/profile/passkey";
import { useSingleFlight } from "../src/hooks";
import { renderWithProviders } from "./render";

/** A `fetch` whose answers the test releases, in order. */
function held() {
  const waiting: ((response: Response) => void)[] = [];
  const answers = {
    requests: 0,
    waiting,
    fetch: () => {
      answers.requests++;
      return new Promise<Response>((resolve) => waiting.push(resolve));
    },
    release: (body: unknown) =>
      waiting.shift()!(new Response(JSON.stringify(body), { status: 200 })),
  };
  return answers;
}

// Ported from Cicada (ui/src/lib/single-flight.test.ts), where the hook
// came from.
describe("useSingleFlight", () => {
  it("drops a call while one is in flight, then takes the next", async () => {
    let finish!: () => void;
    const fn = vi.fn(
      (n: number) =>
        new Promise<number>((resolve) => (finish = () => resolve(n))),
    );
    const { result } = renderHook(() => useSingleFlight(fn));
    let first!: Promise<number | undefined>;
    act(() => {
      first = result.current(1);
    });
    await expect(result.current(2)).resolves.toBeUndefined();
    expect(fn).toHaveBeenCalledTimes(1);
    await act(async () => finish());
    await expect(first).resolves.toBe(1);

    const next = result.current(3);
    await act(async () => finish());
    await expect(next).resolves.toBe(3);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("frees itself after a failure, and calls the latest function", async () => {
    const failing = vi.fn(async () => {
      throw new Error("refused");
    });
    const { result, rerender } = renderHook(
      ({ fn }: { fn: () => Promise<string> }) => useSingleFlight(fn),
      { initialProps: { fn: failing as () => Promise<string> } },
    );
    const call = result.current;
    await expect(call()).rejects.toThrow("refused");
    rerender({ fn: async () => "ok" });
    // The same function, now calling the latest one.
    expect(result.current).toBe(call);
    await expect(call()).resolves.toBe("ok");
  });
});

describe("EnrollPasskey", () => {
  it("begins one enrollment for a double click", async () => {
    setAuthUrl("http://auth.test");
    // The failed passkey prompt is logged.
    vi.spyOn(console, "error").mockImplementation(() => {});
    const begins = held();
    vi.stubGlobal("fetch", begins.fetch);
    renderWithProviders(<EnrollPasskey />);
    const enroll = screen.getByRole("button", { name: "Enroll Passkey 2FA" });
    // In one tick: React hasn't rendered the first click's loading
    // (disabled) state when the second lands.
    act(() => {
      enroll.click();
      enroll.click();
    });
    await waitFor(() => expect(begins.waiting).toHaveLength(1));
    // The second click was dropped, not queued: still one once the
    // first enrollment ended (jsdom has no passkeys, it fails there).
    await act(async () => begins.release({ publicKey: {} }));
    await waitFor(() =>
      expect(enroll.hasAttribute("data-loading")).toBe(false),
    );
    expect(begins.requests).toBe(1);
  });
});
