import type {
  SupporterReadResponses,
  SupporterWriteResponses,
} from "./responses.ts";
import type {
  SupporterReadRequest,
  SupporterWriteRequest,
} from "./types.ts";

/**
 * A failed request, as the promises of `MoghSupporterClient` reject:
 * the shape of `mogh_auth_client`'s.
 */
export type RequestError = {
  /**
   * The http status. `1` when the server wasn't reached (network /
   * CORS failure).
   */
  status: number;
  /**
   * The error body, `{ error, trace }`. `error` is always a string,
   * as are `trace`'s entries: a json body of another shape (eg. the
   * error of a proxy in front of the server) is reported like a body
   * which isn't json.
   */
  result: { error?: string; trace?: string[] } & Record<string, unknown>;
  /** The caught error, if any. */
  error?: unknown;
};

/**
 * The client of the supporter api an app serves (`mogh_supporter`'s
 * `server::router`, mounted at `url`, eg. `https://app.example/supporter`).
 * Requests are authenticated with `jwt` (the app's login token, as
 * `mogh_auth_client` keeps it), or the session cookie.
 */
export function MoghSupporterClient(url: string, jwt?: string) {
  const request = async <Params, Res>(
    path: "/read" | "/write",
    type: string,
    params: Params,
  ): Promise<Res> => {
    let response: Response;
    try {
      response = await fetch(`${url}${path}/${type}`, {
        method: "POST",
        body: JSON.stringify(params),
        headers: {
          "content-type": "application/json",
          ...(jwt ? { authorization: jwt } : {}),
        },
        credentials: "include",
      });
    } catch (error) {
      throw {
        status: 1,
        result: {
          error: "Request failed with error",
          trace: describeError(error),
        },
        error,
      } satisfies RequestError;
    }
    const body = await readBody(response);
    if (!body.read) {
      throw {
        status: response.status,
        result: {
          error: "Failed to get response body",
          trace: describeError(body.error),
        },
        error: body.error,
      } satisfies RequestError;
    }
    if (response.status === 200) {
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
    const error = errorBody(body);
    if (error) {
      throw {
        status: response.status,
        result: { ...error, trace: traceList(error.trace) },
      } satisfies RequestError;
    }
    // Not an error of the server, eg. a proxy's 502 page.
    throw {
      status: response.status,
      result: {
        error: statusMessage(response),
        trace: bodySnippet(body.text),
      },
    } satisfies RequestError;
  };

  /** The read api: `GetSupporterKey` for every user, the rest for admins. */
  const read = async <
    T extends SupporterReadRequest["type"],
    Req extends Extract<SupporterReadRequest, { type: T }>,
  >(
    type: T,
    params: Req["params"],
  ) =>
    await request<Req["params"], SupporterReadResponses[Req["type"]]>(
      "/read",
      type,
      params,
    );

  /** The write api, for admins. */
  const write = async <
    T extends SupporterWriteRequest["type"],
    Req extends Extract<SupporterWriteRequest, { type: T }>,
  >(
    type: T,
    params: Req["params"],
  ) =>
    await request<Req["params"], SupporterWriteResponses[Req["type"]]>(
      "/write",
      type,
      params,
    );

  return { read, write };
}

/**
 * A readable message for a caught error and its causes.
 * `JSON.stringify` gives `{}` for an `Error`.
 */
function describeError(error: unknown): string[] {
  const messages: string[] = [];
  let current = error;
  for (let depth = 0; depth < 5 && current != null; depth++) {
    if (current instanceof Error) {
      messages.push([current.name, current.message].filter(Boolean).join(": "));
      current = current.cause;
    } else {
      messages.push(String(current));
      break;
    }
  }
  const filtered = messages.filter(Boolean);
  return filtered.length ? filtered : ["Unknown error"];
}

type Body =
  /** Reading the body failed. */
  | { read: false; error: unknown }
  | { read: true; text: string; parsed: true; json: unknown }
  | { read: true; text: string; parsed: false; parseError: unknown };

/** The response body, parsed when it is json. */
async function readBody(response: Response): Promise<Body> {
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
 * The parsed error body when it has the shape of the server's errors:
 * an object whose `error` is a string.
 */
function errorBody(
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
function traceList(trace: unknown): string[] {
  return Array.isArray(trace)
    ? trace.filter((line): line is string => typeof line === "string")
    : [];
}

/** The start of a response body which isn't the expected json. */
function bodySnippet(text: string): string[] {
  const snippet = text.replace(/\s+/g, " ").trim();
  if (!snippet) return [];
  return [snippet.length > 500 ? snippet.slice(0, 500) + "..." : snippet];
}

function statusMessage({ status, statusText }: Response) {
  return `Request failed with status ${status} ${statusText}`.trim();
}
