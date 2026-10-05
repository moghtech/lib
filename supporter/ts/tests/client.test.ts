import { afterEach, describe, test } from "node:test";
import assert from "node:assert/strict";
import { MoghSupporterClient, type RequestError } from "../src/index.ts";
import * as fixture from "./fixture.ts";

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

type Call = { url: string; init: RequestInit };

function mockFetch(
  handler: (call: Call) => Response | Promise<Response>,
): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const call = { url: String(url), init: init ?? {} };
    calls.push(call);
    return handler(call);
  }) as typeof fetch;
  return calls;
}

async function rejection(promise: Promise<unknown>): Promise<RequestError> {
  try {
    await promise;
  } catch (e) {
    return e as RequestError;
  }
  assert.fail("resolved");
}

const INFO = {
  source: "Stored",
  config_key: false,
  supporter: null,
  problem: null,
};

describe("MoghSupporterClient", () => {
  test("posts the params to the request's path, with the token", async () => {
    const calls = mockFetch(() => Response.json(fixture.RESPONSE));
    const client = MoghSupporterClient("https://app.example/supporter", "jwt-1");
    const key = await client.read("GetSupporterKey", { nonce: fixture.NONCE });
    assert.deepEqual(key, fixture.RESPONSE);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://app.example/supporter/read/GetSupporterKey");
    assert.equal(calls[0].init.method, "POST");
    assert.equal(calls[0].init.body, JSON.stringify({ nonce: fixture.NONCE }));
    const headers = calls[0].init.headers as Record<string, string>;
    assert.equal(headers.authorization, "jwt-1");
    assert.equal(headers["content-type"], "application/json");
    assert.equal(calls[0].init.credentials, "include");
  });

  test("writes go to /write, without a token header when there is none", async () => {
    const calls = mockFetch(() => Response.json(INFO));
    const client = MoghSupporterClient("https://app.example/supporter");
    const info = await client.write("SetSupporterKey", { key: "a.b.c" });
    assert.deepEqual(info, INFO);
    assert.equal(calls[0].url, "https://app.example/supporter/write/SetSupporterKey");
    assert.equal(calls[0].init.body, JSON.stringify({ key: "a.b.c" }));
    const headers = calls[0].init.headers as Record<string, string>;
    assert.equal("authorization" in headers, false);
    await client.write("DeleteSupporterKey", {});
    assert.equal(calls[1].url, "https://app.example/supporter/write/DeleteSupporterKey");
    assert.equal(calls[1].init.body, "{}");
  });

  test("the branding is read by everyone and written whole", async () => {
    const branding = { icon: "/icons/acme.png", icon_width: 120, replace_home: true };
    const calls = mockFetch(() => Response.json(branding));
    const client = MoghSupporterClient("https://app.example/supporter", "jwt");
    assert.deepEqual(await client.read("GetSupporterBranding", {}), branding);
    assert.equal(calls[0].url, "https://app.example/supporter/read/GetSupporterBranding");
    assert.deepEqual(await client.write("SetSupporterBranding", { branding }), branding);
    assert.equal(calls[1].url, "https://app.example/supporter/write/SetSupporterBranding");
    assert.equal(calls[1].init.body, JSON.stringify({ branding }));
  });

  test("rejects with the server's error", async () => {
    mockFetch(() =>
      Response.json(
        { error: "Invalid supporter key", trace: ["The key has 2 parts separated by `.`, expected 3"] },
        { status: 400 },
      ),
    );
    const client = MoghSupporterClient("https://app.example/supporter", "jwt");
    const e = await rejection(client.write("SetSupporterKey", { key: "a.b" }));
    assert.equal(e.status, 400);
    assert.equal(e.result.error, "Invalid supporter key");
    assert.deepEqual(e.result.trace, ["The key has 2 parts separated by `.`, expected 3"]);
  });

  test("rejects with the status for a body of another shape", async () => {
    mockFetch(
      () => new Response("<html>Bad Gateway</html>", { status: 502, statusText: "Bad Gateway" }),
    );
    const client = MoghSupporterClient("https://app.example/supporter", "jwt");
    const e = await rejection(client.read("GetSupporterKeyInfo", {}));
    assert.equal(e.status, 502);
    assert.equal(e.result.error, "Request failed with status 502 Bad Gateway");
    assert.deepEqual(e.result.trace, ["<html>Bad Gateway</html>"]);
    // A json error of another shape is not passed on as is.
    mockFetch(() => Response.json({ error: { code: 403 } }, { status: 403 }));
    const other = await rejection(client.read("GetSupporterKeyInfo", {}));
    assert.equal(other.status, 403);
    assert.match(other.result.error ?? "", /status 403/);
  });

  test("rejects with status 1 when the server is unreachable", async () => {
    mockFetch(() => {
      throw new TypeError("fetch failed", { cause: new Error("ECONNREFUSED") });
    });
    const client = MoghSupporterClient("https://app.example/supporter", "jwt");
    const e = await rejection(client.read("GetSupporterKey", { nonce: fixture.NONCE }));
    assert.equal(e.status, 1);
    assert.equal(e.result.error, "Request failed with error");
    assert.deepEqual(e.result.trace, ["TypeError: fetch failed", "Error: ECONNREFUSED"]);
  });

  test("rejects a 200 which isn't json", async () => {
    mockFetch(() => new Response("not json", { status: 200 }));
    const client = MoghSupporterClient("https://app.example/supporter", "jwt");
    const e = await rejection(client.read("GetSupporterKey", { nonce: fixture.NONCE }));
    assert.equal(e.status, 200);
    assert.equal(e.result.error, "Invalid response body");
    assert.ok(e.result.trace?.some((line) => line.includes("not json")));
  });
});
