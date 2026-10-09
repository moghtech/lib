import { QueryClient } from "@tanstack/react-query";
import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { setAuthUrl, useLogin, useManageAuth } from "../src/auth/hooks";
import { EnrollTotp } from "../src/auth/profile/totp";
import {
  answering,
  renderHookWithProviders,
  renderWithProviders,
} from "./render";

beforeEach(() => setAuthUrl("http://auth.test"));

/**
 * Lets react-query's notifications reach the hook: they are delivered
 * on a timer (`notifyManager`), after the request's promise resolved.
 */
const flush = () =>
  act(() => new Promise<void>((resolve) => setTimeout(resolve, 0)));

/** A `fetch` whose answers the test releases, in order. */
function held() {
  const waiting: ((response: Response) => void)[] = [];
  const fetch = () => new Promise<Response>((resolve) => waiting.push(resolve));
  const release = (body: unknown) =>
    waiting.shift()!(new Response(JSON.stringify(body), { status: 200 }));
  return { fetch, waiting, release };
}

describe("useManageAuth", () => {
  it("forgets a settled request: its answer and params leave the hook and the cache", async () => {
    // An app's query client with react-query's defaults, which keep a
    // finished mutation for 5 minutes.
    const client = new QueryClient();
    vi.stubGlobal(
      "fetch",
      answering({ key: "K_key", secret: "S_secret" }).fetch,
    );
    const onSuccess = vi.fn();
    const { result } = renderHookWithProviders(
      () => useManageAuth("CreateApiKey", { onSuccess }),
      client,
    );
    await act(() =>
      result.current.mutateAsync({
        name: "ci",
        expires: 0,
        cidr_whitelist: [],
      }),
    );
    await flush();
    // The caller got the secret, to show it once.
    expect(onSuccess.mock.calls[0][0]).toEqual({
      key: "K_key",
      secret: "S_secret",
    });
    expect(result.current.status).toBe("idle");
    expect(result.current.data).toBeUndefined();
    expect(result.current.variables).toBeUndefined();
    await waitFor(() =>
      expect(client.getMutationCache().getAll()).toHaveLength(0),
    );
  });

  it("forgets a failed request's params (a password)", async () => {
    const client = new QueryClient();
    vi.stubGlobal(
      "fetch",
      answering({ error: "Password too short", trace: [] }, 400).fetch,
    );
    const onError = vi.fn();
    const { result } = renderHookWithProviders(
      () => useManageAuth("UpdatePassword", { onError }),
      client,
    );
    await act(() =>
      result.current
        .mutateAsync({ password: "hunter2" })
        .catch(() => undefined),
    );
    await flush();
    // The caller's onError still runs, with the server's error.
    expect(onError.mock.calls[0][0]).toMatchObject({
      status: 400,
      result: { error: "Password too short" },
    });
    expect(result.current.status).toBe("idle");
    expect(result.current.variables).toBeUndefined();
    expect(result.current.error).toBeNull();
    await waitFor(() =>
      expect(client.getMutationCache().getAll()).toHaveLength(0),
    );
  });

  it("stays pending until the last of overlapping requests settled", async () => {
    const answers = held();
    vi.stubGlobal("fetch", answers.fetch);
    const { result } = renderHookWithProviders(() =>
      useManageAuth("UpdateUsername"),
    );
    let first!: Promise<unknown>;
    let second!: Promise<unknown>;
    act(() => {
      first = result.current.mutateAsync({ username: "a" });
    });
    act(() => {
      second = result.current.mutateAsync({ username: "b" });
    });
    await waitFor(() => expect(answers.waiting).toHaveLength(2));
    await act(async () => {
      answers.release({});
      await first;
    });
    await flush();
    expect(result.current.isPending).toBe(true);
    await act(async () => {
      answers.release({});
      await second;
    });
    await flush();
    expect(result.current.status).toBe("idle");
    expect(result.current.variables).toBeUndefined();
  });
});

describe("useLogin", () => {
  it("forgets the password and the token once the login settled", async () => {
    const client = new QueryClient();
    vi.stubGlobal("fetch", answering({ jwt: "J_token" }).fetch);
    const onSuccess = vi.fn();
    const { result } = renderHookWithProviders(
      () => useLogin("SignUpLocalUser", { onSuccess }),
      client,
    );
    await act(() =>
      result.current.mutateAsync({ username: "max", password: "hunter2" }),
    );
    await flush();
    expect(onSuccess.mock.calls[0][0]).toEqual({ jwt: "J_token" });
    expect(result.current.data).toBeUndefined();
    expect(result.current.variables).toBeUndefined();
    await waitFor(() =>
      expect(client.getMutationCache().getAll()).toHaveLength(0),
    );
  });
});

describe("EnrollTotp", () => {
  it("shows a failed begin with Try Again, though the request is forgotten", async () => {
    vi.stubGlobal(
      "fetch",
      answering({ error: "Too many requests", trace: [] }, 429).fetch,
    );
    renderWithProviders(<EnrollTotp />);
    fireEvent.click(screen.getByRole("button", { name: "Enroll TOTP 2FA" }));
    await screen.findByText("The enrollment could not begin");
    screen.getByText(/Too many requests/);

    vi.stubGlobal(
      "fetch",
      answering({ uri: "otpauth://totp/test", png: "" }).fetch,
    );
    fireEvent.click(screen.getByRole("button", { name: "Try Again" }));
    expect(await screen.findByRole("textbox", { name: "URI" })).toHaveProperty(
      "value",
      "otpauth://totp/test",
    );
    expect(screen.queryByText("The enrollment could not begin")).toBeNull();
  });
});
