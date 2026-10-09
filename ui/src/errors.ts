/**
 * The message of the notification for a failed request of a mogh
 * client: the `RequestError` of `mogh_auth_client`, which the
 * supporter client (and the apps' own clients) reject with too.
 *
 * It is the server's error, then the causes of its trace which the
 * error doesn't already show (eg. a failed attempt's error under the
 * rate limit's attempts remaining note), each starting with a capital
 * letter, joined with " | ", and a pointer to the console, where the
 * caller logs the whole error.
 *
 * Takes anything that was caught. An empty error, empty trace lines,
 * or a value which isn't a `RequestError` at all (eg. a `TypeError`)
 * never make it throw: a notification built in an `onError` must show
 * whatever the server (or a proxy in front of it) answered.
 */
export function errorNotificationMessage(e: unknown): string {
  const result = field(e, "result");
  const error = text(field(result, "error"));
  const trace = field(result, "trace");
  const causes = (Array.isArray(trace) ? trace : [])
    .map(text)
    .filter((cause) => cause && !error.includes(cause));
  const parts = error ? [error, ...causes] : causes;
  return [
    ...(parts.length ? parts : ["Unknown error"]).map(capitalize),
    "See console for details",
  ].join(" | ");
}

/** The `key` of `value` when it is an object, else `undefined`. */
function field(value: unknown, key: string): unknown {
  return value && typeof value === "object"
    ? (value as Record<string, unknown>)[key]
    : undefined;
}

/** A string trimmed, anything else empty. */
function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}
