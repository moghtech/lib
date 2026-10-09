import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { notifications, notificationsStore } from "@mantine/notifications";
import {
  clipboardAvailable,
  copyToClipboard,
} from "../src/components/clipboard.ts";

/** What the page was told, as `[color, message]`. */
function shown() {
  return notificationsStore
    .getState()
    .notifications.map(({ color, message }) => [color, message]);
}

let written: string[] = [];
/** A page: a secure context or not, with a clipboard which may refuse. */
function page({
  secure,
  clipboard = true,
  refuse = false,
}: {
  secure: boolean;
  clipboard?: boolean;
  refuse?: boolean;
}) {
  (globalThis as { window?: unknown }).window = { isSecureContext: secure };
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      clipboard: clipboard
        ? {
            writeText: async (text: string) => {
              if (refuse) {
                throw new DOMException(
                  "Write permission denied.",
                  "NotAllowedError",
                );
              }
              written.push(text);
            },
          }
        : undefined,
    },
  });
}

const warned: unknown[][] = [];
console.warn = (...args: unknown[]) => void warned.push(args);

beforeEach(() => {
  notifications.clean();
  written = [];
  warned.length = 0;
});

test("copied: the notification says so", async () => {
  page({ secure: true });
  assert.equal(clipboardAvailable(), true);
  assert.equal(await copyToClipboard("abc", "the URI"), true);
  assert.deepEqual(written, ["abc"]);
  assert.deepEqual(shown(), [["green", "Copied the URI to clipboard."]]);
});

test("on plain http nothing is copied, and the page says why", async () => {
  // `http://192.168.1.10`: no secure context, so no clipboard api.
  for (const options of [
    { secure: false },
    { secure: false, clipboard: false },
    { secure: true, clipboard: false },
  ]) {
    notifications.clean();
    page(options);
    assert.equal(clipboardAvailable(), false);
    assert.equal(await copyToClipboard("abc"), false);
    assert.deepEqual(written, []);
    const [[color, message]] = shown();
    assert.equal(color, "red");
    assert.match(String(message), /isn't served over https\. Select the text/);
  }
});

test("a refused write is no success, and the text isn't logged", async () => {
  page({ secure: true, refuse: true });
  const secret = "recovery-code-1234";
  assert.equal(await copyToClipboard(secret, "code 1"), false);
  const [[color, message]] = shown();
  assert.equal(color, "red");
  assert.match(String(message), /didn't allow copying/);
  assert.equal(warned.length, 1);
  assert.ok(!JSON.stringify(warned.map(String)).includes(secret));
});
