import { notifications } from "@mantine/notifications";

/**
 * Whether the page can write to the clipboard. The clipboard api only
 * exists in a secure context: a page served over https, or from
 * localhost. On a plain http page (eg. an install reached at
 * `http://192.168.1.10`) text has to be selected and copied by hand.
 */
export function clipboardAvailable(): boolean {
  return (
    typeof window !== "undefined" &&
    window.isSecureContext === true &&
    typeof navigator !== "undefined" &&
    typeof navigator.clipboard?.writeText === "function"
  );
}

/**
 * Copies `text` to the clipboard, and says how it went: "Copied
 * `label` to clipboard." once the browser took it, otherwise why it
 * didn't (no secure context, see `clipboardAvailable`, or the browser
 * refused) and that the text can be selected instead. Resolves whether
 * it copied, never rejects. The text itself is never logged.
 */
export async function copyToClipboard(
  text: string,
  label = "content",
): Promise<boolean> {
  if (!clipboardAvailable()) {
    notifications.show({
      message:
        "Can't copy to the clipboard: the page isn't served over https. Select the text to copy it.",
      color: "red",
    });
    return false;
  }
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    console.warn("Copying to the clipboard failed:", e);
    notifications.show({
      message:
        "The browser didn't allow copying to the clipboard. Select the text to copy it.",
      color: "red",
    });
    return false;
  }
  notifications.show({
    message: `Copied ${label} to clipboard.`,
    color: "green",
  });
  return true;
}
