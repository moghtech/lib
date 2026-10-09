import assert from "node:assert/strict";
import http from "node:http";
import { afterEach, describe, it } from "node:test";
import { setLocalStorage } from "./helpers.mjs";

// Like node without `--localstorage-file`, minus the warning.
setLocalStorage({ value: undefined });

// The helpers the apps' clients send their own requests with, from the
// package's entry point.
const {
  credentialHeaders,
  fetchJson,
  fetchResponse,
  requestFailed,
  responseError,
  responseJson,
} = await import("../dist/lib.js");

const realFetch = globalThis.fetch;
/** The requests sent. */
let sent = [];

function mockFetch(respond) {
  sent = [];
  globalThis.fetch = async (input, init) => {
    sent.push({ input, init });
    return respond(input, init);
  };
}

afterEach(() => {
  globalThis.fetch = realFetch;
});

async function rejection(promise) {
  try {
    await promise;
  } catch (e) {
    return e;
  }
  assert.fail("expected the request to fail");
}

/** A response whose body fails to be read, eg. a connection reset. */
function unreadable(status) {
  const body = new ReadableStream({
    start(controller) {
      controller.error(new Error("connection reset"));
    },
  });
  return new Response(body, { status });
}

const NOTES_URL = "https://app.example/read/ListNotes";

describe("fetchJson", () => {
  it("sends the request as given and resolves its json", async () => {
    mockFetch(() => Response.json([{ id: "1" }]));
    const init = {
      method: "POST",
      body: "{}",
      headers: { "content-type": "application/json", authorization: "jwt" },
      credentials: "include",
    };
    assert.deepEqual(await fetchJson(NOTES_URL, init), [{ id: "1" }]);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].input, NOTES_URL);
    assert.deepEqual(sent[0].init, init);
  });

  it("rejects with the server's error, marked as its own", async () => {
    const result = { error: "Not found", trace: ["no note 1"] };
    mockFetch(() => Response.json(result, { status: 404 }));
    assert.deepEqual(await rejection(fetchJson(NOTES_URL)), {
      status: 404,
      result,
      server: true,
    });
  });

  it("doesn't mark an error body without a trace list", async () => {
    // Eg. the 401 of an auth gateway in front of the server, which
    // says nothing about the token the request was sent with.
    for (const [body, trace] of [
      [{ error: "unauthorized" }, []],
      [{ error: "unauthorized", trace: "expired" }, []],
    ]) {
      mockFetch(() => Response.json(body, { status: 401 }));
      assert.deepEqual(await rejection(fetchJson(NOTES_URL)), {
        status: 401,
        result: { ...body, trace },
      });
    }
  });

  it("reports another body by its status and start", async () => {
    mockFetch(
      () =>
        new Response(`<html>\n  ${"x".repeat(600)}\n</html>`, {
          status: 502,
          statusText: "Bad Gateway",
        }),
    );
    const e = await rejection(fetchJson(NOTES_URL));
    assert.equal(e.status, 502);
    assert.equal(e.server, undefined);
    assert.equal(e.result.error, "Request failed with status 502 Bad Gateway");
    // The start of the body, its whitespace collapsed.
    assert.deepEqual(e.result.trace, [
      `<html> ${"x".repeat(600)} </html>`.slice(0, 500) + "...",
    ]);
  });

  it("rejects a 200 which isn't json", async () => {
    // Eg. the login page of an SSO proxy.
    mockFetch(() => new Response("<!doctype html>", { status: 200 }));
    const e = await rejection(fetchJson(NOTES_URL));
    assert.equal(e.status, 200);
    assert.equal(e.result.error, "Invalid response body");
    assert.match(e.result.trace[0], /^SyntaxError: /);
    assert.equal(e.result.trace[1], "<!doctype html>");
    assert.ok(e.error instanceof SyntaxError);
  });

  it("rejects a body which can't be read", async () => {
    for (const status of [200, 500]) {
      mockFetch(() => unreadable(status));
      const e = await rejection(fetchJson(NOTES_URL));
      assert.equal(e.status, status);
      assert.deepEqual(e.result, {
        error: "Failed to get response body",
        trace: ["Error: connection reset"],
      });
      assert.equal(e.error.message, "connection reset");
    }
  });

  it("rejects with status 1 when no response comes", async () => {
    const cause = new Error("connect ECONNREFUSED 127.0.0.1:443");
    globalThis.fetch = async () => {
      throw new TypeError("fetch failed", { cause });
    };
    const e = await rejection(fetchJson(NOTES_URL));
    assert.deepEqual(e.result, {
      error: "Request failed with error",
      trace: [
        "TypeError: fetch failed",
        "Error: connect ECONNREFUSED 127.0.0.1:443",
      ],
    });
    assert.equal(e.status, 1);
    assert.equal(e.error.cause, cause);
  });
});

describe("fetchResponse", () => {
  it("resolves the 200 response itself, its body unread", async () => {
    mockFetch(() => new Response("line 1\nline 2\n"));
    const response = await fetchResponse(NOTES_URL, { method: "POST" });
    assert.equal(response.bodyUsed, false);
    assert.equal(await response.text(), "line 1\nline 2\n");
  });

  it("rejects like fetchJson", async () => {
    const result = { error: "Forbidden", trace: [] };
    mockFetch(() => Response.json(result, { status: 403 }));
    assert.deepEqual(await rejection(fetchResponse(NOTES_URL)), {
      status: 403,
      result,
      server: true,
    });
    globalThis.fetch = async () => {
      throw new TypeError("fetch failed");
    };
    assert.equal((await rejection(fetchResponse(NOTES_URL))).status, 1);
  });
});

describe("the parts", () => {
  it("responseJson reads a response fetched elsewhere", async () => {
    assert.deepEqual(await responseJson(Response.json({ a: 1 })), { a: 1 });
    const e = await rejection(
      responseJson(new Response("busy", { status: 503 })),
    );
    assert.deepEqual(e, {
      status: 503,
      result: { error: "Request failed with status 503", trace: ["busy"] },
    });
  });

  it("responseError resolves what to reject with", async () => {
    const e = await responseError(
      Response.json({ error: "Gone", trace: ["a"], code: 7 }, { status: 410 }),
    );
    assert.deepEqual(e, {
      status: 410,
      result: { error: "Gone", trace: ["a"], code: 7 },
      server: true,
    });
    // A json error of another shape is not passed on as is.
    for (const foreign of [{ error: { code: 403 } }, ["Forbidden"], null]) {
      assert.deepEqual(
        await responseError(Response.json(foreign, { status: 403 })),
        {
          status: 403,
          result: {
            error: "Request failed with status 403",
            trace: [JSON.stringify(foreign)],
          },
        },
      );
    }
  });

  it("requestFailed describes any caught value", () => {
    // Causes are followed five deep.
    let error = new Error("0");
    for (let i = 1; i < 8; i++) error = new Error(String(i), { cause: error });
    assert.deepEqual(requestFailed(error).result.trace, [
      "Error: 7",
      "Error: 6",
      "Error: 5",
      "Error: 4",
      "Error: 3",
    ]);
    assert.deepEqual(requestFailed("aborted").result.trace, ["aborted"]);
    assert.deepEqual(requestFailed(new Error("")).result.trace, ["Error"]);
    assert.deepEqual(requestFailed(undefined), {
      status: 1,
      result: { error: "Request failed with error", trace: ["Unknown error"] },
      error: undefined,
    });
  });
});

describe("credentialHeaders", () => {
  it("builds the headers of a credential", () => {
    assert.deepEqual(credentialHeaders("jwt-1"), { authorization: "jwt-1" });
    assert.deepEqual(credentialHeaders({ jwt: "jwt-1" }), {
      authorization: "jwt-1",
    });
    assert.deepEqual(credentialHeaders({ key: "k", secret: "s" }), {
      "x-api-key": "k",
      "x-api-secret": "s",
    });
    assert.deepEqual(
      credentialHeaders({ jwt: undefined, key: "k", secret: "s" }),
      { "x-api-key": "k", "x-api-secret": "s" },
    );
    assert.deepEqual(credentialHeaders({ jwt: "j", key: "k", secret: "s" }), {
      authorization: "j",
    });
    for (const none of [undefined, null, "", {}, { key: "k" }, { jwt: 1 }]) {
      assert.deepEqual(credentialHeaders(none), {}, JSON.stringify(none));
    }
  });
});

/**
 * A local http server answering with `respond(req, body)` (status,
 * headers, body), and the requests it received.
 */
async function serve(t, respond) {
  const received = [];
  const server = http.createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    received.push({ method: req.method, headers: req.headers, body });
    const [status, headers, text] = respond(req, body);
    res.writeHead(status, headers);
    res.end(text);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  return { url: `http://127.0.0.1:${server.address().port}`, received };
}

describe("redirects", () => {
  const apiKey = { "x-api-key": "K_key_K", "x-api-secret": "S_s3cr3t_S" };

  it("a request with an api key doesn't follow them", async () => {
    mockFetch(() => Response.json({}));
    for (const headers of [
      apiKey,
      { "X-API-KEY": "k" },
      { "x-api-secret": "s" },
      new Headers(apiKey),
      Object.entries(apiKey),
    ]) {
      await fetchJson(NOTES_URL, { method: "POST", headers });
      await fetchResponse(NOTES_URL, { method: "POST", headers });
    }
    assert.equal(sent.length, 10);
    for (const { init } of sent) assert.equal(init.redirect, "error");
  });

  it("other requests, and a request choosing, are left as they are", async () => {
    mockFetch(() => Response.json({}));
    const jwt = { method: "POST", headers: { authorization: "jwt" } };
    await fetchJson(NOTES_URL, jwt);
    await fetchJson(NOTES_URL);
    const follow = { headers: apiKey, redirect: "follow" };
    await fetchJson(NOTES_URL, follow);
    assert.equal(sent[0].init, jwt);
    assert.equal(sent[0].init.redirect, undefined);
    assert.equal(sent[1].init, undefined);
    assert.equal(sent[2].init.redirect, "follow");
  });

  it("the api key doesn't reach where a redirect points", async (t) => {
    // Eg. an SSO proxy in front of the server sending requests to its
    // login page, on another origin.
    const elsewhere = await serve(t, () => [200, {}, "{}"]);
    const server = await serve(t, () => [
      307,
      { location: `${elsewhere.url}/login` },
      "",
    ]);
    const e = await rejection(
      fetchJson(`${server.url}/read/ListNotes`, {
        method: "POST",
        body: "{}",
        headers: { "content-type": "application/json", ...apiKey },
      }),
    );
    assert.equal(e.status, 1);
    assert.equal(e.result.error, "Request failed with error");
    assert.ok(
      e.result.trace.some((line) => /redirect/i.test(line)),
      e.result.trace.join(" | "),
    );
    assert.equal(server.received.length, 1);
    assert.equal(elsewhere.received.length, 0);
  });

  it("why: fetch sends any header but Authorization on", async (t) => {
    const elsewhere = await serve(t, () => [200, {}, "{}"]);
    const server = await serve(t, () => [
      307,
      { location: `${elsewhere.url}/login` },
      "",
    ]);
    // Following, as `fetch` does by default.
    await fetchJson(`${server.url}/read/ListNotes`, {
      method: "POST",
      body: '{"password":"p"}',
      headers: { authorization: "jwt", ...apiKey },
      redirect: "follow",
    });
    const [request] = elsewhere.received;
    assert.equal(request.headers.authorization, undefined);
    assert.equal(request.headers["x-api-secret"], "S_s3cr3t_S");
    // A 307 sends the body again.
    assert.equal(request.method, "POST");
    assert.equal(request.body, '{"password":"p"}');
  });
});
