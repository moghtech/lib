import { credentialToJSON } from "./passkey.js";
import {
  bodySnippet,
  credentialHeaders,
  describeError,
  errorBody,
  fetchJson,
  readBody,
  statusMessage,
  traceList,
  type ClientCredential,
} from "./request.js";
import type { LoginResponses, ManageResponses } from "./responses.js";
import type {
  LoginRequest,
  ManageRequest,
  TokenExchangeError,
  TokenExchangeResponse,
} from "./types.js";

export * as Types from "./types.js";
export * as Passkey from "./passkey.js";
export {
  LOGIN_TOKENS,
  createLoginTokens,
  extractUserIdFromJwt,
  isTokenRefusal,
} from "./tokens.js";
export type { LoginToken, LoginTokensStore } from "./tokens.js";
export {
  credentialHeaders,
  fetchJson,
  fetchResponse,
  requestFailed,
  responseError,
  responseJson,
} from "./request.js";
export type { ClientCredential, RequestError } from "./request.js";
export type { LoginResponses, ManageResponses };

/**
 * The error message of a manage request refused with `403` because it
 * needs a recent login starts with this. Requests which change how a user
 * can log in (password, 2fa, linked logins, new api keys, ...) are only
 * accepted with a token issued a short while ago. Send the user to
 * log in again, and retry.
 */
export const REAUTHENTICATION_REQUIRED = "Reauthentication required";

/**
 * Whether a rejected request (`{ status, result }`) needs the user to log
 * in again. Takes anything that was caught: it never throws, and is
 * `false` for any other value.
 */
export function isReauthenticationRequired(e: unknown): boolean {
  try {
    if (!e || typeof e !== "object") return false;
    const { status, result } = e as { status?: unknown; result?: unknown };
    if (status !== 403 || !result || typeof result !== "object") {
      return false;
    }
    const error = (result as { error?: unknown }).error;
    return (
      typeof error === "string" && error.startsWith(REAUTHENTICATION_REQUIRED)
    );
  } catch {
    // Eg. a getter which throws.
    return false;
  }
}

/** RFC 8693 identifiers used by the token endpoint. */
export const TOKEN_EXCHANGE = {
  GRANT_TYPE: "urn:ietf:params:oauth:grant-type:token-exchange",
  ID_TOKEN: "urn:ietf:params:oauth:token-type:id_token",
  JWT: "urn:ietf:params:oauth:token-type:jwt",
  ACCESS_TOKEN: "urn:ietf:params:oauth:token-type:access_token",
} as const;

/**
 * The path to return to after logging in: `backto` when it is a path
 * on `origin`, otherwise `/`. Check the `backto` query of the login
 * page with it before navigating there, it comes from the url and can
 * be anything (`//evil.example`, `javascript:...`).
 *
 * Only a relative path starting with a single `/` is accepted. The
 * result is the normalized path, and one which only resolves to
 * `//...` (`/.//host`, `/%2e//host`) has its leading slashes
 * collapsed, so it can't be read as a protocol relative url.
 * @param backto Default: the `backto` query of the current location.
 * @param origin Default: the current origin.
 */
export function safeBackto(
  backto: string | null = new URLSearchParams(location.search).get(
    "backto",
  ),
  origin: string = location.origin,
): string {
  // Only a path: not a scheme, host or `//host`.
  if (!backto?.startsWith("/") || /^\/[\/\\]/.test(backto)) return "/";
  try {
    const base = new URL(origin);
    const target = new URL(backto, base);
    if (target.origin !== base.origin) return "/";
    // Removing dot segments can give `//host`.
    const path = target.pathname.replace(/^[\/\\]+/, "/");
    return path + target.search + target.hash;
  } catch {
    return "/";
  }
}

/**
 * Whether `pathname` is the login page's own route, `/login` (or
 * `/login/`). Not any path starting with it, like an app's
 * `/login-providers/:id`: a login started there returns there.
 */
function isLoginPath(pathname: string): boolean {
  return pathname === "/login" || pathname === "/login/";
}

/** The requests which send a passkey credential. */
const PASSKEY_CREDENTIAL_REQUESTS = [
  "CompletePasskeyLogin",
  "ConfirmPasskeyEnrollment",
];

/**
 * The params to send. A passkey credential is sent in its JSON form,
 * see `Passkey.credentialToJSON`.
 */
function encodeParams(type: string, params: unknown) {
  if (!PASSKEY_CREDENTIAL_REQUESTS.includes(type)) return params;
  const credential = (params as { credential?: unknown } | undefined)
    ?.credential;
  if (!credential || typeof credential !== "object") return params;
  try {
    return {
      ...(params as object),
      credential: credentialToJSON(credential),
    };
  } catch {
    // Not a credential this can encode, the server reports it.
    return params;
  }
}

/**
 * The client of the auth api mounted at `url`, eg.
 * `https://example.com/auth`.
 *
 * `credential` authenticates its manage requests: a JWT (a string, eg.
 * `LOGIN_TOKENS.jwt()`, or `{ jwt }`), or an api key (`{ key, secret }`),
 * which the server takes for the requests open to api keys (eg.
 * `GetUserId`, `DeleteApiKey`, and the login provider / trusted issuer
 * requests of an admin). An app client passes the credential it was
 * created with, its `{ jwt, key, secret }` as is. Without one the
 * requests only carry the session cookie.
 */
export function MoghAuthClient(url: string, credential?: ClientCredential) {
  const headers = {
    "content-type": "application/json",
    ...credentialHeaders(credential),
  };

  const request = async <Params, Res>(
    path: "/login" | "/manage",
    type: string,
    params: Params
  ): Promise<Res> =>
    await fetchJson<Res>(`${url}${path}/${type}`, {
      method: "POST",
      body: JSON.stringify(encodeParams(type, params)),
      headers,
      credentials: "include",
    });

  const login = async <
    T extends LoginRequest["type"],
    Req extends Extract<LoginRequest, { type: T }>
  >(
    type: T,
    params: Req["params"]
  ) =>
    await request<Req["params"], LoginResponses[Req["type"]]>(
      "/login",
      type,
      params
    );

  const manage = async <
    T extends ManageRequest["type"],
    Req extends Extract<ManageRequest, { type: T }>
  >(
    type: T,
    params: Req["params"]
  ) =>
    await request<Req["params"], ManageResponses[Req["type"]]>(
      "/manage",
      type,
      params
    );

  /**
   * Redirect to log in with an external login provider. From the login
   * page (`/login`) the provider sends the user back to its `backto`
   * (checked with `safeBackto`), from anywhere else back to the
   * current page.
   * @param providerSlug The provider `slug` from `GetLoginOptions`.
   */
  const externalLogin = (providerSlug: string) => {
    const _redirect = isLoginPath(location.pathname)
      ? location.origin + safeBackto()
      : location.href;
    const redirect = encodeURIComponent(_redirect);
    location.replace(
      `${url}/external/${encodeURIComponent(providerSlug)}/login?redirect=${redirect}`
    );
  };

  /**
   * The url to redirect to in order to link the signed in user to an
   * external login provider. `BeginExternalLoginLink` must be called
   * first, with the same `slug`: the link is begun for one provider,
   * and the `/link` route refuses another.
   * @param providerSlug The provider `slug` from `GetLoginOptions`.
   */
  const externalLinkUrl = (providerSlug: string) =>
    `${url}/external/${encodeURIComponent(providerSlug)}/link`;

  /**
   * Link the signed in user to an external login provider.
   * Begins the link on the session, then redirects to the provider.
   * @param providerSlug The provider `slug` from `GetLoginOptions`.
   */
  const externalLink = async (providerSlug: string) => {
    await manage("BeginExternalLoginLink", { slug: providerSlug });
    location.replace(externalLinkUrl(providerSlug));
  };

  /**
   * RFC 8693 Token Exchange: exchange a token issued by an external
   * login provider (an ID token / JWT) for an app token, without
   * sending the user through the browser.
   *
   * The provider must have token exchange enabled,
   * and the user must already exist.
   *
   * Rejects with `{ status, result }`, where `result` is the
   * OAuth error: `{ error, error_description }`. A response which isn't
   * an OAuth error (no string `error`, eg. a proxy's error page) is
   * `server_error`, its status and body in `error_description`. Other
   * fields of an OAuth error body are kept, except that an
   * `error_description` which isn't a string is dropped and a `trace`
   * is reduced to its string lines, as `RequestError.result` declares.
   *
   * @param subjectToken The token issued by the provider.
   * @param subjectTokenType `TOKEN_EXCHANGE.ID_TOKEN` (default) or `TOKEN_EXCHANGE.JWT`.
   */
  const tokenExchange = async (
    subjectToken: string,
    subjectTokenType:
      | typeof TOKEN_EXCHANGE.ID_TOKEN
      | typeof TOKEN_EXCHANGE.JWT = TOKEN_EXCHANGE.ID_TOKEN
  ): Promise<TokenExchangeResponse> => {
    let response: Response;
    try {
      // The RFC requires a form, not json.
      response = await fetch(`${url}/token`, {
        method: "POST",
        body: new URLSearchParams({
          grant_type: TOKEN_EXCHANGE.GRANT_TYPE,
          subject_token: subjectToken,
          subject_token_type: subjectTokenType,
        }),
      });
    } catch (error) {
      throw {
        status: 1,
        result: {
          error: "server_error",
          error_description: [
            "Request failed with error",
            ...describeError(error),
          ].join(" | "),
        } satisfies TokenExchangeError,
        error,
      };
    }
    const body = await readBody(response);
    if (!body.read) {
      throw {
        status: response.status,
        result: {
          error: "server_error",
          error_description: [
            "Failed to get response body",
            ...describeError(body.error),
          ].join(" | "),
        } satisfies TokenExchangeError,
        error: body.error,
      };
    }
    if (body.parsed && response.status === 200) {
      return body.json as TokenExchangeResponse;
    }
    const error = errorBody(body);
    if (error) {
      const { error_description, ...rest } = error;
      throw {
        status: response.status,
        result: {
          ...rest,
          // Not sent by the auth server, but a body which has one
          // keeps `RequestError.result`'s shape.
          ...("trace" in rest ? { trace: traceList(rest.trace) } : {}),
          ...(typeof error_description === "string"
            ? { error_description }
            : {}),
        } satisfies TokenExchangeError,
      };
    }
    // Not an OAuth error, eg. a proxy's 502 page,
    // or its json error of another shape.
    const description =
      response.status === 200 && !body.parsed
        ? ["Invalid response body", ...describeError(body.parseError)]
        : [statusMessage(response)];
    throw {
      status: response.status,
      result: {
        error: "server_error",
        error_description: [...description, ...bodySnippet(body.text)].join(
          " | ",
        ),
      } satisfies TokenExchangeError,
      ...(body.parsed ? {} : { error: body.parseError }),
    };
  };

  return {
    login,
    manage,
    tokenExchange,
    externalLogin,
    externalLinkUrl,
    externalLink,
  };
}
