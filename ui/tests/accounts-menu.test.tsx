import { act, fireEvent, screen } from "@testing-library/react";
import * as MoghAuth from "mogh_auth_client";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { currentUserId } from "../src/auth/accounts";
import { AccountChange, AccountsMenu } from "../src/auth/accounts-menu";
import { reloadPage } from "../src/auth/reload";
import { renderWithProviders } from "./render";

// jsdom implements no reload: the menu's is recorded instead.
vi.mock("../src/auth/reload", () => ({ reloadPage: vi.fn() }));

const base64Url = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");
/** A token of `sub`, as the store reads it (it doesn't verify it). */
const jwt = (sub: string) =>
  `${base64Url({ alg: "none" })}.${base64Url({ sub })}.sig`;

/** The users signed in, in the store's order. */
const signedIn = () =>
  MoghAuth.LOGIN_TOKENS.accounts().map((account) => account.user_id);

type Confirm = (change: AccountChange) => boolean | Promise<boolean>;

/**
 * The menu of a tab signed in as `alice`, with `bob` signed in too,
 * opened. `onSignOut` records the users signed out.
 */
function openMenu(confirmAccountChange?: Confirm) {
  const onSignOut = vi.fn();
  renderWithProviders(
    <AccountsMenu
      user={{ id: "alice", username: "alice" }}
      useAccountInfo={(userId) => ({ username: userId })}
      onSignOut={onSignOut}
      confirmAccountChange={confirmAccountChange}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Account: alice" }));
  return { onSignOut };
}

/** Lets an answer of the app (a promise) arrive. */
const settle = () =>
  act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });

beforeEach(() => {
  vi.mocked(reloadPage).mockClear();
  MoghAuth.LOGIN_TOKENS.remove_all();
  MoghAuth.LOGIN_TOKENS.add_and_change(jwt("bob"));
  MoghAuth.LOGIN_TOKENS.add_and_change(jwt("alice"));
});

describe("AccountsMenu switching accounts", () => {
  it("asks first, and a refusal leaves the account and the page", async () => {
    const confirm = vi.fn<Confirm>(() => false);
    openMenu(confirm);
    fireEvent.click(screen.getByRole("button", { name: "bob" }));
    await settle();
    expect(confirm).toHaveBeenCalledExactlyOnceWith({
      action: "switch",
      userId: "bob",
    });
    expect(currentUserId()).toBe("alice");
    expect(reloadPage).not.toHaveBeenCalled();
  });

  it("switches and reloads once the app agreed, asked before anything changed", async () => {
    let asked: string | undefined;
    openMenu(async () => {
      asked = currentUserId();
      return true;
    });
    fireEvent.click(screen.getByRole("button", { name: "bob" }));
    await settle();
    expect(asked).toBe("alice");
    expect(currentUserId()).toBe("bob");
    expect(reloadPage).toHaveBeenCalledOnce();
  });

  it("switches and reloads at once without a handler", () => {
    openMenu();
    fireEvent.click(screen.getByRole("button", { name: "bob" }));
    expect(currentUserId()).toBe("bob");
    expect(reloadPage).toHaveBeenCalledOnce();
  });

  it("asks once while an answer is pending, and stays on an error", async () => {
    let answer: (confirmed: boolean) => void = () => {};
    const confirm = vi.fn<Confirm>(
      () => new Promise((resolve) => (answer = resolve)),
    );
    openMenu(confirm);
    const bob = screen.getByRole("button", { name: "bob" });
    fireEvent.click(bob);
    fireEvent.click(bob);
    expect(confirm).toHaveBeenCalledOnce();
    await act(async () => answer(false));
    expect(currentUserId()).toBe("alice");

    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    confirm.mockImplementation(() => {
      throw new Error("the app's dialog failed");
    });
    fireEvent.click(bob);
    await settle();
    expect(confirm).toHaveBeenCalledTimes(2);
    expect(error).toHaveBeenCalled();
    expect(currentUserId()).toBe("alice");
    expect(reloadPage).not.toHaveBeenCalled();
  });
});

describe("AccountsMenu signing out", () => {
  it("asks before signing this tab's account out, a refusal keeps it", async () => {
    const confirm = vi.fn<Confirm>(() => false);
    const { onSignOut } = openMenu(confirm);
    fireEvent.click(screen.getByRole("button", { name: "Log out accounts" }));
    fireEvent.click(screen.getByRole("button", { name: "Log out alice" }));
    await settle();
    expect(confirm).toHaveBeenCalledExactlyOnceWith({
      action: "sign-out",
      userId: "alice",
    });
    expect(signedIn()).toEqual(expect.arrayContaining(["alice", "bob"]));
    expect(currentUserId()).toBe("alice");
    expect(onSignOut).not.toHaveBeenCalled();
    expect(reloadPage).not.toHaveBeenCalled();
  });

  it("signs this tab's account out and reloads once the app agreed", async () => {
    const { onSignOut } = openMenu(() => true);
    fireEvent.click(screen.getByRole("button", { name: "Log out accounts" }));
    fireEvent.click(screen.getByRole("button", { name: "Log out alice" }));
    await settle();
    expect(signedIn()).toEqual(["bob"]);
    expect(onSignOut).toHaveBeenCalledExactlyOnceWith(["alice"]);
    expect(reloadPage).toHaveBeenCalledOnce();
  });

  it("signs another account out without asking, the tab stays", async () => {
    const confirm = vi.fn<Confirm>(() => false);
    const { onSignOut } = openMenu(confirm);
    fireEvent.click(screen.getByRole("button", { name: "Log out accounts" }));
    fireEvent.click(screen.getByRole("button", { name: "Log out bob" }));
    await settle();
    expect(confirm).not.toHaveBeenCalled();
    expect(signedIn()).toEqual(["alice"]);
    expect(currentUserId()).toBe("alice");
    expect(onSignOut).toHaveBeenCalledExactlyOnceWith(["bob"]);
    expect(reloadPage).not.toHaveBeenCalled();
  });

  it("asks before logging out all, a refusal keeps every account", async () => {
    const confirm = vi.fn<Confirm>(async () => false);
    const { onSignOut } = openMenu(confirm);
    fireEvent.click(screen.getByRole("button", { name: "Log out accounts" }));
    fireEvent.click(screen.getByRole("button", { name: "Log Out All" }));
    await settle();
    expect(confirm).toHaveBeenCalledExactlyOnceWith({
      action: "sign-out-all",
    });
    expect(signedIn()).toHaveLength(2);
    expect(currentUserId()).toBe("alice");
    expect(onSignOut).not.toHaveBeenCalled();
    expect(reloadPage).not.toHaveBeenCalled();
  });

  it("logs out all and reloads once the app agreed", async () => {
    const { onSignOut } = openMenu(async () => true);
    fireEvent.click(screen.getByRole("button", { name: "Log out accounts" }));
    fireEvent.click(screen.getByRole("button", { name: "Log Out All" }));
    await settle();
    expect(signedIn()).toEqual([]);
    expect(currentUserId()).toBeUndefined();
    expect(onSignOut).toHaveBeenCalledOnce();
    expect([...onSignOut.mock.calls[0][0]].sort()).toEqual(["alice", "bob"]);
    expect(reloadPage).toHaveBeenCalledOnce();
  });

  it("signs out and reloads at once without a handler", () => {
    const { onSignOut } = openMenu();
    fireEvent.click(screen.getByRole("button", { name: "Log out accounts" }));
    fireEvent.click(screen.getByRole("button", { name: "Log out alice" }));
    expect(signedIn()).toEqual(["bob"]);
    expect(onSignOut).toHaveBeenCalledExactlyOnceWith(["alice"]);
    expect(reloadPage).toHaveBeenCalledOnce();

    fireEvent.click(screen.getByRole("button", { name: "Log Out All" }));
    expect(signedIn()).toEqual([]);
    expect(reloadPage).toHaveBeenCalledTimes(2);
  });
});
