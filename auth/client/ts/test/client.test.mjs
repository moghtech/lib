import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { setLocalStorage } from "./helpers.mjs";

// Like node without `--localstorage-file`, minus the warning.
setLocalStorage({ value: undefined });

const {
  MoghAuthClient,
  REAUTHENTICATION_REQUIRED,
  isReauthenticationRequired,
  isTokenRefusal,
  safeBackto,
} = await import("../dist/lib.js");

const realFetch = globalThis.fetch;
/** The requests sent by the client. */
let sent = [];

function mockFetch(respond) {
  sent = [];
  globalThis.fetch = async (url, init) => {
    sent.push({ url, init });
    return respond();
  };
}

afterEach(() => {
  globalThis.fetch = realFetch;
});

const client = MoghAuthClient("https://auth.example");

async function rejection(promise) {
  try {
    await promise;
  } catch (e) {
    return e;
  }
  assert.fail("expected the request to fail");
}

describe("request errors", () => {
  it("keeps the status and body of a non json error", async () => {
    mockFetch(
      () =>
        new Response("<html>\n<h1>502 Bad Gateway</h1>\n</html>", {
          status: 502,
          statusText: "Bad Gateway",
        }),
    );
    const e = await rejection(client.login("GetLoginOptions", {}));
    assert.equal(e.status, 502);
    assert.deepEqual(e.result, {
      error: "Request failed with status 502 Bad Gateway",
      trace: ["<html> <h1>502 Bad Gateway</h1> </html>"],
    });
  });

  it("handles an empty error body", async () => {
    mockFetch(() => new Response(null, { status: 404 }));
    const e = await rejection(client.manage("GetUserId", {}));
    assert.equal(e.status, 404);
    assert.deepEqual(e.result, {
      error: "Request failed with status 404",
      trace: [],
    });
  });

  it("passes the json error of the server through", async () => {
    const result = { error: "Invalid credentials", trace: ["cause"] };
    mockFetch(() => Response.json(result, { status: 401 }));
    const e = await rejection(client.login("LoginLocalUser", {}));
    // Marked as the server's own answer.
    assert.deepEqual(e, { status: 401, result, server: true });
  });

  it("describes a network failure", async () => {
    sent = [];
    globalThis.fetch = async () => {
      throw new TypeError("fetch failed", {
        cause: new Error("connect ECONNREFUSED 127.0.0.1:443"),
      });
    };
    const e = await rejection(client.login("GetLoginOptions", {}));
    assert.equal(e.status, 1);
    assert.deepEqual(e.result, {
      error: "Request failed with error",
      trace: [
        "TypeError: fetch failed",
        "Error: connect ECONNREFUSED 127.0.0.1:443",
      ],
    });
  });

  it("reports an invalid 200 body apart from network failures", async () => {
    // Eg. the auth url points at the ui, which serves index.html.
    mockFetch(() => new Response("<!doctype html>", { status: 200 }));
    const e = await rejection(client.login("GetLoginOptions", {}));
    assert.equal(e.status, 200);
    assert.equal(e.result.error, "Invalid response body");
    assert.match(e.result.trace[0], /^SyntaxError: /);
    assert.equal(e.result.trace[1], "<!doctype html>");
  });

  it("reports a json error of another shape like a non json one", async () => {
    // Eg. a gateway / WAF in front of the auth api.
    for (const foreign of [
      { error: { code: 403, message: "Forbidden" } },
      { error: true, message: "Forbidden" },
      { message: "Forbidden" },
      ["Forbidden"],
      "Forbidden",
      403,
      null,
    ]) {
      mockFetch(() =>
        Response.json(foreign, { status: 403, statusText: "Forbidden" }),
      );
      const e = await rejection(client.manage("UpdatePassword", {}));
      assert.deepEqual(
        e,
        {
          status: 403,
          result: {
            error: "Request failed with status 403 Forbidden",
            trace: [JSON.stringify(foreign)],
          },
        },
        JSON.stringify(foreign),
      );
      assert.equal(isReauthenticationRequired(e), false);
    }
  });

  it("keeps only the string lines of the trace", async () => {
    // Only a `trace` list is the server's own error body.
    for (const [trace, expected, server] of [
      [undefined, [], false],
      ["cause", [], false],
      [{ 0: "cause" }, [], false],
      [["cause", 1, null, { a: 1 }, "root"], ["cause", "root"], true],
    ]) {
      mockFetch(() =>
        Response.json(
          { error: "Forbidden", trace, code: 7 },
          { status: 403 },
        ),
      );
      const e = await rejection(client.manage("UpdatePassword", {}));
      assert.deepEqual(e, {
        status: 403,
        result: { error: "Forbidden", trace: expected, code: 7 },
        ...(server ? { server: true } : {}),
      });
    }
  });

  it("tells a reauthentication error apart", async () => {
    const error = `${REAUTHENTICATION_REQUIRED}: this needs a recent login`;
    mockFetch(() => Response.json({ error, trace: [] }, { status: 403 }));
    const e = await rejection(client.manage("UpdatePassword", {}));
    assert.equal(isReauthenticationRequired(e), true);
    // Only as a 403.
    assert.equal(
      isReauthenticationRequired({ status: 401, result: { error } }),
      false,
    );
  });

  it("resolves the json body", async () => {
    mockFetch(() => Response.json({ user_id: "x" }));
    assert.deepEqual(await client.manage("GetUserId", {}), {
      user_id: "x",
    });
  });
});

describe("credentials", () => {
  /** The credential headers of the requests `client` sends. */
  async function credentialHeadersOf(client) {
    mockFetch(() => Response.json({}));
    await client.manage("GetUserId", {});
    await client.login("GetLoginOptions", {});
    assert.equal(sent.length, 2);
    // The same on every request.
    assert.deepEqual(sent[0].init.headers, sent[1].init.headers);
    const { "content-type": contentType, ...credentials } =
      sent[0].init.headers;
    assert.equal(contentType, "application/json");
    assert.equal(sent[0].init.credentials, "include");
    return credentials;
  }

  it("sends a jwt as authorization", async () => {
    for (const credential of ["jwt-1", { jwt: "jwt-1" }]) {
      assert.deepEqual(
        await credentialHeadersOf(
          MoghAuthClient("https://auth.example", credential),
        ),
        { authorization: "jwt-1" },
      );
      // `fetch` drops it on a redirect to another origin.
      for (const { init } of sent) assert.equal(init.redirect, undefined);
    }
  });

  it("sends an api key as X-API-KEY / X-API-SECRET", async () => {
    // Eg. `komodo.auth.manage("DeleteApiKey", ..)` from a script.
    assert.deepEqual(
      await credentialHeadersOf(
        MoghAuthClient("https://auth.example", { key: "k", secret: "s" }),
      ),
      { "x-api-key": "k", "x-api-secret": "s" },
    );
    // Without following redirects, which would take it elsewhere.
    for (const { init } of sent) assert.equal(init.redirect, "error");
  });

  it("takes an app client's state as is", async () => {
    // `{ jwt, key, secret }`, the unused ones undefined.
    const apiKey = { jwt: undefined, key: "k", secret: "s" };
    assert.deepEqual(
      await credentialHeadersOf(MoghAuthClient("https://auth.example", apiKey)),
      { "x-api-key": "k", "x-api-secret": "s" },
    );
    // A jwt goes first, as in the apps' clients.
    const both = { jwt: "jwt-1", key: "k", secret: "s" };
    assert.deepEqual(
      await credentialHeadersOf(MoghAuthClient("https://auth.example", both)),
      { authorization: "jwt-1" },
    );
  });

  it("sends none without a whole credential", async () => {
    for (const credential of [
      undefined,
      "",
      {},
      { jwt: "" },
      { jwt: undefined, key: undefined, secret: undefined },
      { key: "k" },
      { key: "k", secret: "" },
      { secret: "s" },
    ]) {
      assert.deepEqual(
        await credentialHeadersOf(
          MoghAuthClient("https://auth.example", credential),
        ),
        {},
        JSON.stringify(credential),
      );
    }
  });
});

describe("tokenExchange errors", () => {
  it("keeps the status of a non json error", async () => {
    mockFetch(
      () =>
        new Response("upstream timeout", {
          status: 504,
          statusText: "Gateway Timeout",
        }),
    );
    const e = await rejection(client.tokenExchange("token"));
    assert.equal(e.status, 504);
    assert.deepEqual(e.result, {
      error: "server_error",
      error_description:
        "Request failed with status 504 Gateway Timeout | upstream timeout",
    });
  });

  it("passes the oauth error through", async () => {
    const result = { error: "invalid_grant", error_description: "expired" };
    mockFetch(() => Response.json(result, { status: 400 }));
    const e = await rejection(client.tokenExchange("token"));
    assert.deepEqual(e, { status: 400, result });
  });

  it("reports a json error of another shape as server_error", async () => {
    for (const foreign of [
      { error: { code: 429 }, error_description: "slow down" },
      { message: "Too Many Requests" },
      ["temporarily_unavailable"],
      "temporarily_unavailable",
    ]) {
      mockFetch(() =>
        Response.json(foreign, {
          status: 429,
          statusText: "Too Many Requests",
        }),
      );
      const e = await rejection(client.tokenExchange("token"));
      assert.deepEqual(
        e,
        {
          status: 429,
          result: {
            error: "server_error",
            error_description: `Request failed with status 429 Too Many Requests | ${JSON.stringify(foreign)}`,
          },
        },
        JSON.stringify(foreign),
      );
    }
  });

  it("drops an error_description which isn't a string", async () => {
    mockFetch(() =>
      Response.json(
        { error: "temporarily_unavailable", error_description: { a: 1 } },
        { status: 503 },
      ),
    );
    const e = await rejection(client.tokenExchange("token"));
    assert.deepEqual(e, {
      status: 503,
      result: { error: "temporarily_unavailable" },
    });
  });

  it("keeps only the string lines of a trace", async () => {
    for (const [trace, expected] of [
      ["s", []],
      [null, []],
      [{ a: 1 }, []],
      [["cause", 1, null, { a: 1 }, "root"], ["cause", "root"]],
    ]) {
      mockFetch(() =>
        Response.json(
          { error: "temporarily_unavailable", trace, code: 7 },
          { status: 503 },
        ),
      );
      const e = await rejection(client.tokenExchange("token"));
      assert.deepEqual(
        e,
        {
          status: 503,
          result: {
            error: "temporarily_unavailable",
            trace: expected,
            code: 7,
          },
        },
        JSON.stringify(trace),
      );
    }
  });

  it("describes a network failure", async () => {
    globalThis.fetch = async () => {
      throw new TypeError("fetch failed");
    };
    const e = await rejection(client.tokenExchange("token"));
    assert.equal(e.status, 1);
    assert.equal(
      e.result.error_description,
      "Request failed with error | TypeError: fetch failed",
    );
  });
});

describe("isTokenRefusal", () => {
  it("is the server refusing the token", async () => {
    mockFetch(() =>
      Response.json(
        { error: "Invalid token", trace: ["expired"] },
        { status: 401 },
      ),
    );
    const e = await rejection(client.manage("GetUserId", {}));
    assert.equal(isTokenRefusal(e), true);
  });

  it("only for the given statuses", async () => {
    // Eg. a disabled user: the session is over for `GetUserId`, not
    // for a request the user lacks a permission for.
    mockFetch(() =>
      Response.json({ error: "User disabled", trace: [] }, { status: 403 }),
    );
    const e = await rejection(client.manage("GetUserId", {}));
    assert.equal(isTokenRefusal(e), false);
    assert.equal(isTokenRefusal(e, [401, 403]), true);
  });

  it("not a proxy's or a gateway's answer", async () => {
    // An auth gateway in front of the server says nothing about the
    // token sent to the server.
    for (const response of [
      () => Response.json({ error: "unauthorized" }, { status: 401 }),
      () => new Response("<h1>401 Authorization Required</h1>", {
        status: 401,
      }),
    ]) {
      mockFetch(response);
      const e = await rejection(client.manage("GetUserId", {}));
      assert.equal(e.status, 401);
      assert.equal(isTokenRefusal(e), false);
    }
  });

  it("is false for anything else, without throwing", () => {
    const throwing = {
      get status() {
        throw new Error("getter");
      },
    };
    for (const [i, e] of [
      undefined,
      null,
      401,
      "401",
      {},
      { status: 401 },
      { status: "401", server: true },
      { status: 1, server: true },
      { status: 429, server: true },
      { status: 500, server: true },
      { status: 401, server: "true" },
      throwing,
    ].entries()) {
      assert.equal(isTokenRefusal(e), false, `case ${i}`);
    }
    assert.equal(isTokenRefusal({ status: 401, server: true }), true);
  });
});

describe("isReauthenticationRequired", () => {
  const error = `${REAUTHENTICATION_REQUIRED}: this needs a recent login`;

  it("is true for the reauthentication error", () => {
    assert.equal(
      isReauthenticationRequired({ status: 403, result: { error } }),
      true,
    );
  });

  it("is false for anything else, without throwing", () => {
    const throwing = {
      status: 403,
      get result() {
        throw new Error("getter");
      },
    };
    for (const e of [
      undefined,
      null,
      "",
      error,
      403,
      [],
      {},
      { status: 403 },
      { status: 403, result: null },
      { status: 403, result: error },
      { status: 403, result: { error: { code: 403 } } },
      { status: 403, result: { error: 403 } },
      { status: 403, result: { error: true } },
      { status: 403, result: { error: [error] } },
      { status: 403, result: { error: "Forbidden" } },
      { status: "403", result: { error } },
      { status: 401, result: { error } },
      throwing,
      new Proxy(
        {},
        {
          get() {
            throw new Error("proxy");
          },
        },
      ),
    ]) {
      assert.equal(isReauthenticationRequired(e), false);
    }
  });
});

describe("passkey requests", () => {
  // A credential without `toJSON`, its fields on the prototype
  // like the browser's `PublicKeyCredential`.
  class LegacyCredential {
    get id() {
      return "AQID";
    }
    get rawId() {
      return new Uint8Array([1, 2, 3]).buffer;
    }
    get type() {
      return "public-key";
    }
    get response() {
      return {
        clientDataJSON: new Uint8Array([4]).buffer,
        authenticatorData: new Uint8Array([5]).buffer,
        signature: new Uint8Array([6]).buffer,
        userHandle: null,
      };
    }
    getClientExtensionResults() {
      return {};
    }
  }

  it("sends the credential in its json form", async () => {
    mockFetch(() => Response.json({ type: "UserId", data: "x" }));
    await client.login("CompletePasskeyLogin", {
      credential: new LegacyCredential(),
    });
    assert.equal(sent.length, 1);
    assert.deepEqual(JSON.parse(sent[0].init.body), {
      credential: {
        id: "AQID",
        rawId: "AQID",
        type: "public-key",
        authenticatorAttachment: null,
        clientExtensionResults: {},
        response: {
          clientDataJSON: "BA",
          authenticatorData: "BQ",
          signature: "Bg",
          userHandle: null,
        },
      },
    });
  });

  it("leaves other requests alone", async () => {
    mockFetch(() => Response.json({}));
    await client.manage("UpdateUsername", { username: "credential" });
    assert.deepEqual(JSON.parse(sent[0].init.body), {
      username: "credential",
    });
  });
});

describe("safeBackto", () => {
  const origin = "https://app.example";
  for (const [backto, expected] of [
    ["/stacks/1?tab=logs#top", "/stacks/1?tab=logs#top"],
    ["/", "/"],
    [null, "/"],
    ["", "/"],
    ["@evil.example", "/"],
    [".evil.example", "/"],
    [":8443/x", "/"],
    ["https://evil.example/x", "/"],
    ["//evil.example/x", "/"],
    ["/\\evil.example/x", "/"],
    ["/\t/evil.example/x", "/"],
    ["javascript:alert(1)", "/"],
    ["/a/../b", "/b"],
    // Paths which only resolve to `//host` once dot segments are removed.
    ["/.//evil.example", "/evil.example"],
    ["/..//evil.example/x", "/evil.example/x"],
    ["/%2e//evil.example", "/evil.example"],
    ["/a/..//evil.example", "/evil.example"],
    ["/./\\evil.example", "/evil.example"],
    ["/./\\/evil.example?a=1#b", "/evil.example?a=1#b"],
  ]) {
    it(`${JSON.stringify(backto)} -> ${expected}`, () => {
      const path = safeBackto(backto, origin);
      assert.equal(path, expected);
      // Wherever it is navigated to, it stays on the origin.
      assert.equal(new URL(path, origin).origin, origin);
    });
  }
});

describe("externalLogin", () => {
  const origin = "https://app.example";
  const hadLocation = Object.hasOwn(globalThis, "location");
  const realLocation = globalThis.location;

  afterEach(() => {
    if (hadLocation) {
      Object.defineProperty(globalThis, "location", {
        configurable: true,
        writable: true,
        value: realLocation,
      });
    } else {
      delete globalThis.location;
    }
  });

  /** Runs `externalLogin` at `path`, returns where it redirected to. */
  function externalLoginAt(path, providerSlug = "oidc") {
    const current = new URL(path, origin);
    const replaced = [];
    Object.defineProperty(globalThis, "location", {
      configurable: true,
      writable: true,
      value: {
        origin: current.origin,
        href: current.href,
        pathname: current.pathname,
        search: current.search,
        hash: current.hash,
        replace: (url) => replaced.push(url),
      },
    });
    client.externalLogin(providerSlug);
    assert.equal(replaced.length, 1);
    return new URL(replaced[0]);
  }

  for (const [path, expected] of [
    // The login page: back to its (checked) `backto`.
    ["/login?backto=%2Fstacks%2F1%3Ftab%3Dlogs", "/stacks/1?tab=logs"],
    ["/login/?backto=%2Fstacks%2F1", "/stacks/1"],
    ["/login", "/"],
    ["/login?backto=%2F%2Fevil.example", "/"],
    ["/login?backto=https%3A%2F%2Fevil.example", "/"],
    // Anywhere else: back to the current page, `backto` or not.
    ["/login-providers/abc", "/login-providers/abc"],
    [
      "/login-providers/abc?backto=%2Fstacks%2F1",
      "/login-providers/abc?backto=%2Fstacks%2F1",
    ],
    ["/loginx?backto=%2Fstacks%2F1", "/loginx?backto=%2Fstacks%2F1"],
    ["/login/extra?backto=%2Fstacks%2F1", "/login/extra?backto=%2Fstacks%2F1"],
    ["/stacks/1?tab=logs#top", "/stacks/1?tab=logs#top"],
    ["/", "/"],
  ]) {
    it(`${path} -> ${expected}`, () => {
      const target = externalLoginAt(path);
      assert.equal(target.origin, "https://auth.example");
      assert.equal(target.pathname, "/external/oidc/login");
      assert.equal(target.searchParams.get("redirect"), origin + expected);
    });
  }

  it("encodes the provider slug", () => {
    const target = externalLoginAt("/login", "a b/c?d");
    assert.equal(target.pathname, "/external/a%20b%2Fc%3Fd/login");
    assert.equal(target.searchParams.get("redirect"), origin + "/");
  });
});
