// How a request to a mogh server is sent and how its failures are
// reported. `MoghAuthClient` sends its requests with these, and so do
// the clients of the apps for their own apis: every client then
// rejects with the same `RequestError`, which the UIs handle in one
// place for auth and app requests alike.

/**
 * A failed request, as the promises of `MoghAuthClient` and
 * `fetchJson` reject.
 */
export type RequestError = {
  /**
   * The http status. `1` when the server wasn't reached (network /
   * CORS failure), or answered with a redirect which a request
   * carrying an api key doesn't follow.
   */
  status: number;
  /**
   * The error body: `{ error, trace }` (`{ error, error_description }`
   * for `tokenExchange`). `error` is always a string, as are `trace`'s
   * entries and `error_description`: a json body of another shape (eg.
   * the error of a proxy in front of the server) is reported like a body
   * which isn't json.
   */
  result: { error: string; trace?: string[] } & Record<string, unknown>;
  /**
   * Set when `result` is the server's own error body: json with a
   * string `error` and a `trace` list, as a mogh server answers. Not for
   * the error page of a proxy, nor for the `401` / `403` of an auth
   * gateway in front of the server: those say nothing about the
   * credentials the request was sent with.
   */
  server?: true;
  /** The caught error, if any. */
  error?: unknown;
};

/**
 * The credential a client sends with its requests:
 * - a JWT, sent as `Authorization`. A string is the shorthand
 *   of `{ jwt }`.
 * - an api key, sent as `X-API-KEY` / `X-API-SECRET`.
 *
 * A `jwt` is sent when set, otherwise the api key when both `key` and
 * `secret` are, otherwise nothing: the request then only carries the
 * session cookie (`credentials: "include"`). So the state of an app
 * client, `{ jwt, key, secret }` with the unused ones `undefined`, can
 * be passed as is.
 */
export type ClientCredential =
  | string
  | { jwt?: string | undefined }
  | { key: string; secret: string };

/** The headers of an api key, as `credentialHeaders` sends it. */
const API_KEY_HEADERS = ["x-api-key", "x-api-secret"];

/**
 * The headers which send `credential` (see `ClientCredential`). Send a
 * request with an api key through `fetchJson` / `fetchResponse`, or
 * with `redirect: "error"` (see `fetchResponse`).
 */
export function credentialHeaders(
  credential: ClientCredential | undefined,
): Record<string, string> {
  if (!credential) return {};
  if (typeof credential === "string") return { authorization: credential };
  const { jwt, key, secret } = credential as {
    jwt?: unknown;
    key?: unknown;
    secret?: unknown;
  };
  if (typeof jwt === "string" && jwt) return { authorization: jwt };
  if (typeof key === "string" && key && typeof secret === "string" && secret) {
    return { "x-api-key": key, "x-api-secret": secret };
  }
  return {};
}

/**
 * What a request which got no response rejects with: `status: 1`, the
 * caught error and its causes as the `trace`.
 */
export function requestFailed(error: unknown): RequestError {
  return {
    status: 1,
    result: {
      error: "Request failed with error",
      trace: describeError(error),
    },
    error,
  };
}

/**
 * What a response other than `200` rejects with: the server's error
 * body when it has its shape (an object whose `error` is a string,
 * keeping only the string lines of its `trace`), otherwise the status
 * and the start of the body.
 */
export async function responseError(
  response: Response,
): Promise<RequestError> {
  const body = await readBody(response);
  if (!body.read) return bodyNotRead(response, body.error);
  const error = errorBody(body);
  if (error) {
    return {
      status: response.status,
      result: { ...error, trace: traceList(error.trace) },
      ...(Array.isArray(error.trace) ? { server: true as const } : {}),
    };
  }
  // Not an error of the server, eg. a proxy's 502 page,
  // or its json error of another shape.
  return {
    status: response.status,
    result: {
      error: statusMessage(response),
      trace: bodySnippet(body.text),
    },
  };
}

/**
 * The json body of a `200` response. Rejects with a `RequestError`
 * otherwise (`responseError`), also when the body can't be read or
 * isn't json: eg. the login page of an SSO proxy, or the app's own
 * `index.html` when the url points at the UI rather than the api.
 */
export async function responseJson<Res>(response: Response): Promise<Res> {
  if (response.status !== 200) throw await responseError(response);
  const body = await readBody(response);
  if (!body.read) throw bodyNotRead(response, body.error);
  if (body.parsed) return body.json as Res;
  throw {
    status: response.status,
    result: {
      error: "Invalid response body",
      trace: [...describeError(body.parseError), ...bodySnippet(body.text)],
    },
    error: body.parseError,
  } satisfies RequestError;
}

/**
 * Send a request with `fetch`, and resolve with its `200` response,
 * eg. to stream the body. Rejects with a `RequestError` otherwise:
 * `requestFailed` when no response came, `responseError` for another
 * status.
 *
 * A request carrying an api key (`X-API-KEY` / `X-API-SECRET`) doesn't
 * follow redirects, unless `init.redirect` says otherwise: a redirect
 * rejects with `status: 1`. `fetch` outside a browser (node, Deno, a
 * Komodo Action) drops only `Authorization` (and the browser's
 * cookies) on a redirect to another origin, and sends the other
 * headers on to wherever it points: the login page of an SSO proxy in
 * front of the server, or the new address of a server which moved,
 * would get the api key, and a `307` / `308` sends the body again too.
 * A JWT in `Authorization` is safe to follow with.
 */
export async function fetchResponse(
  input: string | URL,
  init?: RequestInit,
): Promise<Response> {
  let response: Response;
  try {
    // Inside the `try`: invalid headers throw a TypeError, as `fetch`
    // would.
    response = await fetch(input, withRedirectPolicy(init));
  } catch (error) {
    throw requestFailed(error);
  }
  if (response.status !== 200) throw await responseError(response);
  return response;
}

/**
 * `init` with `redirect: "error"` when it carries an api key and
 * doesn't set `redirect` itself (see `fetchResponse`).
 */
function withRedirectPolicy(
  init: RequestInit | undefined,
): RequestInit | undefined {
  if (!init || init.redirect !== undefined) return init;
  const headers = new Headers(init.headers);
  if (!API_KEY_HEADERS.some((name) => headers.has(name))) return init;
  return { ...init, redirect: "error" };
}

/**
 * Send a request with `fetch`, and resolve with its json response.
 * Rejects with a `RequestError` on any failure (see `fetchResponse`
 * and `responseJson`), never with anything else.
 *
 * ```ts
 * const notes = await fetchJson<Note[]>(`${url}/read/ListNotes`, {
 *   method: "POST",
 *   body: JSON.stringify({}),
 *   headers: { "content-type": "application/json", authorization: jwt },
 * });
 * ```
 */
export async function fetchJson<Res>(
  input: string | URL,
  init?: RequestInit,
): Promise<Res> {
  return await responseJson<Res>(await fetchResponse(input, init));
}

// The parts below are shared with `tokenExchange`, whose errors have
// the OAuth shape. They aren't exported from the package.

/**
 * A readable message for a caught error and its causes.
 * `JSON.stringify` gives `{}` for an `Error`.
 */
export function describeError(error: unknown): string[] {
  const messages: string[] = [];
  let current = error;
  for (let depth = 0; depth < 5 && current != null; depth++) {
    if (current instanceof Error) {
      messages.push(
        [current.name, current.message].filter(Boolean).join(": "),
      );
      current = current.cause;
    } else {
      messages.push(String(current));
      break;
    }
  }
  const filtered = messages.filter(Boolean);
  return filtered.length ? filtered : ["Unknown error"];
}

export type Body =
  /** Reading the body failed. */
  | { read: false; error: unknown }
  | { read: true; text: string; parsed: true; json: unknown }
  | { read: true; text: string; parsed: false; parseError: unknown };

/** The response body, parsed when it is json. */
export async function readBody(response: Response): Promise<Body> {
  let text: string;
  try {
    text = await response.text();
  } catch (error) {
    return { read: false, error };
  }
  try {
    return { read: true, text, parsed: true, json: JSON.parse(text) };
  } catch (parseError) {
    return { read: true, text, parsed: false, parseError };
  }
}

/**
 * The parsed error body when it has the shape of the server's
 * errors: an object whose `error` is a string. Other json (the error of
 * a proxy / gateway, eg. `{ "error": { "code": 403 } }`) is not passed
 * on as is, it would break the declared shape of `RequestError.result`.
 */
export function errorBody(
  body: Body,
): (Record<string, unknown> & { error: string }) | undefined {
  if (!body.read || !body.parsed) return undefined;
  const { json } = body;
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    return undefined;
  }
  const { error } = json as { error?: unknown };
  return typeof error === "string"
    ? (json as Record<string, unknown> & { error: string })
    : undefined;
}

/** The strings of `trace`, when it is a list. */
export function traceList(trace: unknown): string[] {
  return Array.isArray(trace)
    ? trace.filter((line): line is string => typeof line === "string")
    : [];
}

/** The start of a response body which isn't the expected json. */
export function bodySnippet(text: string): string[] {
  const snippet = text.replace(/\s+/g, " ").trim();
  if (!snippet) return [];
  return [snippet.length > 500 ? snippet.slice(0, 500) + "..." : snippet];
}

export function statusMessage({ status, statusText }: Response) {
  return `Request failed with status ${status} ${statusText}`.trim();
}

/** What a response whose body can't be read rejects with. */
function bodyNotRead(response: Response, error: unknown): RequestError {
  return {
    status: response.status,
    result: {
      error: "Failed to get response body",
      trace: describeError(error),
    },
    error,
  };
}
