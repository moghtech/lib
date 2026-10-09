import { Popover } from "@mantine/core";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { setAuthUrl } from "../src/auth/hooks";
import { EnrollTotp } from "../src/auth/profile/totp";
import {
  HoldOpen,
  RevealOnce,
  useHoldOpen,
} from "../src/components/reveal-once";
import { renderWithProviders } from "./render";

/**
 * A create popover holding open while its form shows a value once (as
 * Cicada's create forms do).
 */
function Example({
  values = [{ label: "Secret", value: "S_secret_S" }],
  confirmSaved = true,
}: {
  values?: { label: string; value: string }[];
  confirmSaved?: boolean;
}) {
  const [opened, setOpened] = useState(false);
  const { held, setHeld } = useHoldOpen();
  return (
    <Popover
      opened={opened}
      onChange={setOpened}
      closeOnClickOutside={!held}
      closeOnEscape={!held}
    >
      <Popover.Target>
        <button type="button" onClick={() => held || setOpened((o) => !o)}>
          Create Thing
        </button>
      </Popover.Target>
      <Popover.Dropdown>
        <HoldOpen.Provider value={setHeld}>
          <Form
            close={() => setOpened(false)}
            values={values}
            confirmSaved={confirmSaved}
          />
        </HoldOpen.Provider>
      </Popover.Dropdown>
    </Popover>
  );
}

function Form({
  close,
  values,
  confirmSaved,
}: {
  close: () => void;
  values: { label: string; value: string }[];
  confirmSaved: boolean;
}) {
  const [created, setCreated] = useState(false);
  if (created) {
    return (
      <RevealOnce
        message="Save it."
        values={values}
        onDone={close}
        confirmSaved={confirmSaved}
      >
        <span>How to use it</span>
      </RevealOnce>
    );
  }
  return (
    <button type="button" onClick={() => setCreated(true)}>
      Submit
    </button>
  );
}

const open = () =>
  fireEvent.click(screen.getByRole("button", { name: "Create Thing" }));

describe("RevealOnce confirmSaved (ported from Cicada's ShownOnce)", () => {
  it("the container closes on a click outside or Escape while nothing shows", () => {
    renderWithProviders(<Example />);
    open();
    fireEvent.mouseDown(document.body);
    expect(screen.queryByText("Submit")).toBeNull();

    open();
    fireEvent.keyDown(screen.getByText("Submit"), { key: "Escape" });
    expect(screen.queryByText("Submit")).toBeNull();
  });

  it("holds a value against stray clicks, Escape and its toggle", () => {
    renderWithProviders(<Example />);
    open();
    fireEvent.click(screen.getByText("Submit"));
    const secret = screen.getByDisplayValue("S_secret_S");

    fireEvent.mouseDown(document.body);
    fireEvent.keyDown(secret, { key: "Escape" });
    open();
    screen.getByDisplayValue("S_secret_S");
  });

  it("asks whether it was saved before Done closes, with a way back", () => {
    renderWithProviders(<Example />);
    open();
    fireEvent.click(screen.getByText("Submit"));

    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    screen.getByText(/^Did you save it\?/);
    // Still held while asking.
    fireEvent.mouseDown(document.body);
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    screen.getByDisplayValue("S_secret_S");

    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    fireEvent.click(screen.getByRole("button", { name: "Saved, close" }));
    expect(screen.queryByDisplayValue("S_secret_S")).toBeNull();
    expect(screen.queryByText(/^Did you save it\?/)).toBeNull();

    // Released: a reopened form closes on a click outside again.
    open();
    screen.getByText("Submit");
    fireEvent.mouseDown(document.body);
    expect(screen.queryByText("Submit")).toBeNull();
  });

  it("closes on Done at once when nothing secret shows", () => {
    renderWithProviders(<Example values={[]} />);
    open();
    fireEvent.click(screen.getByText("Submit"));
    screen.getByText("How to use it");
    // Nothing to lose: not held either.
    fireEvent.mouseDown(document.body);
    expect(screen.queryByText("How to use it")).toBeNull();
  });

  it("without it, as before: no hold, Done closes at once", () => {
    renderWithProviders(<Example confirmSaved={false} />);
    open();
    fireEvent.click(screen.getByText("Submit"));
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(screen.queryByDisplayValue("S_secret_S")).toBeNull();
    expect(screen.queryByText(/^Did you save it\?/)).toBeNull();
  });
});

describe("EnrollTotp's recovery codes", () => {
  it("hold the dialog open until they were saved", async () => {
    setAuthUrl("http://auth.test");
    const codes = Array.from({ length: 10 }, (_, i) => `code-${i}`);
    vi.stubGlobal("fetch", async (url: string) =>
      Response.json(
        url.endsWith("/BeginTotpEnrollment")
          ? { uri: "otpauth://totp/test", png: "" }
          : { recovery_codes: codes },
      ),
    );
    renderWithProviders(<EnrollTotp />);
    fireEvent.click(screen.getByRole("button", { name: "Enroll TOTP 2FA" }));
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Confirm Code" }),
      {
        target: { value: "123456" },
      },
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    const first = await screen.findByRole("textbox", { name: "Code 1" });

    // Neither Escape nor a close button loses them.
    fireEvent.keyDown(first, { key: "Escape" });
    screen.getByRole("textbox", { name: "Code 1" });
    expect(screen.queryByRole("button", { name: "Close" })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    screen.getByText(/^Did you save them\?/);
    fireEvent.click(screen.getByRole("button", { name: "Saved, close" }));
    await waitFor(() =>
      expect(screen.queryByText("Save recovery keys")).toBeNull(),
    );
  });
});
