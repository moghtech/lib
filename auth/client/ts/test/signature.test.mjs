import assert from "node:assert/strict";
import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { afterEach, describe, it } from "node:test";
import { setLocalStorage } from "./helpers.mjs";

// Like node without `--localstorage-file`, minus the warning.
setLocalStorage({ value: undefined });

const {
  API_HOST_HEADER,
  API_NONCE_HEADER,
  API_PUBLIC_KEY_HEADER,
  API_SIGNATURE_HEADER,
  API_TIMESTAMP_HEADER,
  MoghAuthClient,
  OTHER_CREDENTIALS,
  SIGNED_AT_ANOTHER_TIME,
  SIGNED_REQUEST_VERSION,
  checkSignedRequest,
  credentialHeaders,
  credentialSigner,
  fetchSignedJson,
  generateSigningKey,
  looksLikeAPath,
  randomNonce,
  requestSigner,
  signRequest,
  signedMessage,
  signedRequestHeaders,
  signedRequestHeadersForUrl,
  signingKeys,
  urlHost,
  urlPathAndQuery,
  validHost,
  validNonce,
} = await import("../dist/lib.js");

// The example key of RFC 8410: any other implementation of the
// signature (mogh_auth_client's Rust `test_signature_vector`, the
// Terraform provider's Go signer, `openssl pkeyutl -sign -rawin` over
// the message) comes out the same.
const VECTOR_PRIVATE =
  "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC";
const VECTOR_PUBLIC =
  "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
const VECTOR_SIGNATURE =
  "6bjRdFlvAuIZdoF5TkwRxSbdaW4hlMGmr2/b8EA7kJk8kvlXlG/dCfaJv7BdFs25rxNJNvRIrlcl7/S7YuRcAg==";
const VECTOR_BODY = '{"type":"GetUserId","params":{}}';
const NONCE = "0123456789abcdef0123456789abcdef";
/** sha256 of empty input. */
const EMPTY_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/** Whether `signature` (base64) is `publicKey`'s (base64 spki) over `message`. */
function verifies(publicKey, message, signature) {
  const key = createPublicKey({
    key: Buffer.from(publicKey, "base64"),
    format: "der",
    type: "spki",
  });
  return nodeVerify(
    null,
    Buffer.from(message),
    key,
    Buffer.from(signature, "base64"),
  );
}

/** The message the five headers of a request sign, as a server rebuilds it. */
async function messageOf(headers, method, pathAndQuery, body) {
  return await signedMessage({
    host: headers[API_HOST_HEADER],
    method,
    pathAndQuery,
    timestamp: Number(headers[API_TIMESTAMP_HEADER]),
    nonce: headers[API_NONCE_HEADER],
    body,
  });
}

/** `der` as a pem of `label`, 64 characters a line. */
function pem(label, der) {
  const lines = der
    .toString("base64")
    .match(/.{1,64}/g)
    .join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

const realFetch = globalThis.fetch;
/** The requests sent. */
let sent = [];

/** Answer each `fetch` with the next of `responses` (a function of the request, or a `Response`). */
function mockFetch(...responses) {
  sent = [];
  globalThis.fetch = async (input, init) => {
    sent.push({ input, init });
    const next = responses.shift();
    if (!next) throw new Error("unexpected request");
    return typeof next === "function" ? next(input, init) : next;
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

describe("the signature", () => {
  it("reproduces the cross-language vector", async () => {
    const keys = await signingKeys(VECTOR_PRIVATE);
    assert.equal(keys.publicKey, VECTOR_PUBLIC);
    const request = {
      host: "example.com",
      method: "POST",
      pathAndQuery: "/read?x=1",
      timestamp: 1718000000000,
      nonce: NONCE,
      body: VECTOR_BODY,
    };
    assert.equal(
      await signedMessage(request),
      `${SIGNED_REQUEST_VERSION}\nexample.com\nPOST\n/read?x=1\n1718000000000\n${NONCE}\n1063e6f54ccbb0c3e238533021c0952c1cd6c646f177a3bd44b396d640d8a0d8`,
    );
    assert.equal(SIGNED_REQUEST_VERSION, "MOGH1-ED25519");
    assert.equal(await signRequest(keys, request), VECTOR_SIGNATURE);
    // Bytes sign the same as the string.
    assert.equal(
      await signRequest(keys, { ...request, body: Buffer.from(VECTOR_BODY) }),
      VECTOR_SIGNATURE,
    );
  });

  it("keeps the message format stable", async () => {
    // The cases of signature.rs `test_message_format_is_stable`: the
    // server builds the same string to verify the signature.
    const request = (method, pathAndQuery, body) => ({
      host: "example.com",
      method,
      pathAndQuery,
      timestamp: 1234,
      nonce: NONCE,
      body,
    });
    assert.equal(
      await signedMessage(request("POST", "/auth/manage?x=1", "")),
      `MOGH1-ED25519\nexample.com\nPOST\n/auth/manage?x=1\n1234\n${NONCE}\n${EMPTY_SHA256}`,
    );
    assert.equal(
      await signedMessage(request("POST", "/read", "{}")),
      `MOGH1-ED25519\nexample.com\nPOST\n/read\n1234\n${NONCE}\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a`,
    );
    // Every field is signed as it is given: methods are case sensitive.
    assert.notEqual(
      await signedMessage(request("post", "/read", "{}")),
      await signedMessage(request("POST", "/read", "{}")),
    );
  });

  it("refuses a request no server could accept", async () => {
    const ok = {
      host: "example.com",
      method: "POST",
      pathAndQuery: "/read?x=1",
      timestamp: 1234,
      nonce: NONCE,
      body: "",
    };
    checkSignedRequest(ok);
    for (const [change, reason] of [
      [{ host: "Example.com" }, /Invalid host/],
      [{ host: "https://example.com" }, /Invalid host/],
      [{ host: "" }, /Invalid host/],
      [{ method: "" }, /Invalid method/],
      [{ method: "PO ST" }, /Invalid method/],
      [{ pathAndQuery: "read" }, /Invalid path/],
      [{ pathAndQuery: "/read#x" }, /Invalid path/],
      [{ pathAndQuery: "/read x" }, /Invalid path/],
      [{ nonce: "short" }, /Invalid nonce/],
      [{ nonce: "0123456789abcdef!" }, /Invalid nonce/],
    ]) {
      assert.throws(() => checkSignedRequest({ ...ok, ...change }), reason);
    }
    const keys = await signingKeys(VECTOR_PRIVATE);
    await assert.rejects(
      signRequest(keys, { ...ok, host: "Example.com" }),
      /Invalid host/,
    );
  });
});

describe("private key forms", () => {
  const der = Buffer.from(VECTOR_PRIVATE, "base64");
  const seed = der.subarray(16);
  const rawPublic = Buffer.from(VECTOR_PUBLIC, "base64").subarray(12);

  it("takes pkcs8 as pem, base64 der v1 and v2, deriving the public key", async () => {
    // v2 (RFC 5958): version 1, the public key as attribute [1].
    const v2 = Buffer.concat([
      Buffer.from("3053020101300506032b657004220420", "hex"),
      seed,
      Buffer.from("a12303210000", "hex").subarray(0, 5),
      rawPublic,
    ]);
    for (const form of [
      VECTOR_PRIVATE,
      `  ${VECTOR_PRIVATE}\n`,
      pem("PRIVATE KEY", der),
      v2.toString("base64"),
      pem("PRIVATE KEY", v2),
    ]) {
      const keys = await signingKeys(form);
      assert.equal(keys.publicKey, VECTOR_PUBLIC, form);
      assert.equal(keys.privateKey.extractable, false);
      assert.deepEqual(keys.privateKey.usages, ["sign"]);
      // Inline (a key a person writes down) takes pkcs8 alike.
      assert.equal(
        (await signingKeys(form, { inline: true })).publicKey,
        VECTOR_PUBLIC,
      );
    }
  });

  it("takes a raw value of 32 characters or fewer as the seed, as given", async () => {
    // A random key a server hands out: its 32 characters are the seed.
    const raw = "O_wrf7UfNcg7F7pdF5nWxwBQ2M-g2D_O";
    assert.equal(raw.length, 32);
    const asPkcs8 = Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(raw),
    ]).toString("base64");
    const expected = (await signingKeys(asPkcs8)).publicKey;
    assert.equal((await signingKeys(raw)).publicKey, expected);
    assert.equal(
      (await signingKeys(raw, { inline: true })).publicKey,
      expected,
    );
    // Shorter: zero padded, exactly as given (not trimmed).
    const short = " seed ";
    const padded = Buffer.alloc(32);
    padded.set(Buffer.from(short));
    const shortPkcs8 = Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      padded,
    ]).toString("base64");
    assert.equal(
      (await signingKeys(short)).publicKey,
      (await signingKeys(shortPkcs8)).publicKey,
    );
    // A key a person writes down may not be that short.
    await assert.rejects(
      signingKeys(short, { inline: true }),
      /shorter than 32 bytes/,
    );
  });

  it("refuses what is no key, never repeating the value", async () => {
    const secret =
      "MC4CAQAwBQYDK2VwBCIEIHAVKMcPlmL8PMCXghyZNgXtVWeFvyaQ3DpN4wRN3Wcp";
    const x25519 = Buffer.concat([
      Buffer.from("302e020100300506032b656e04220420", "hex"),
      seed,
    ]).toString("base64");
    for (const [value, reason, options] of [
      ["", /Private key is empty/],
      ["   \n", /Private key is empty/],
      ["file:/etc/cicada/keys/device.key", /looks like a file path/],
      ["./device.key", /looks like a file path/],
      ["~/keys/device", /looks like a file path/],
      ["C:\\keys\\device", /looks like a file path/],
      ["/etc/cicada/keys/device.pem", /looks like a file path/],
      ["/etc/cicada/keys/device", /looks like a file path/],
      ["\0".repeat(32), /all zero/],
      [x25519, /X25519/],
      [pem("PRIVATE KEY", Buffer.from(x25519, "base64")), /X25519/],
      [pem("PUBLIC KEY", der), /PRIVATE KEY/],
      [
        "-----BEGIN PRIVATE KEY-----\nnot base64!\n-----END PRIVATE KEY-----",
        /pem/,
      ],
      [
        "not a key, and longer than thirty-two bytes",
        /32 characters or less, or pkcs8/,
      ],
      [`${secret}x`, /32 characters or less, or pkcs8/],
      [VECTOR_PUBLIC, /pkcs8/],
      [
        "not a key, and longer than thirty-two bytes",
        /pkcs8 encoded/,
        { inline: true },
      ],
    ]) {
      const e = await rejection(signingKeys(value, options));
      assert.match(e.message, reason, JSON.stringify(value));
      if (value.length > 8) {
        assert.ok(!e.message.includes(value.trim()), e.message);
      }
    }
  });

  it("tells a path from a raw key", () => {
    for (const path of [
      "file:/etc/key",
      "FILE:/etc/key",
      "./key",
      "../key",
      "~/key",
      ".\\key",
      "C:/keys/k",
      "keys/device.KEY",
      "/etc/cicada/keys/device",
    ]) {
      assert.ok(looksLikeAPath(path), path);
    }
    for (const key of [
      VECTOR_PRIVATE,
      "O_wrf7UfNcg7F7pdF5nWxwBQ2M-g2D_O",
      "keys/device",
      "$HOME/key",
      // An absolute path which reads as random base64 of a raw key's length.
      "/Ab3/Ab3/Ab3/Ab3/Ab3/Ab3/Ab3/Ab3",
    ]) {
      assert.ok(!looksLikeAPath(key), key);
    }
  });

  it("generates a pair the signer takes", async () => {
    const { privateKey, publicKey } = await generateSigningKey();
    const der = Buffer.from(privateKey, "base64");
    assert.equal(der.length, 48);
    assert.equal(
      der.subarray(0, 16).toString("hex"),
      "302e020100300506032b657004220420",
    );
    assert.equal(Buffer.from(publicKey, "base64").length, 44);
    const keys = await signingKeys(privateKey, { inline: true });
    assert.equal(keys.publicKey, publicKey);
    const other = await generateSigningKey();
    assert.notEqual(other.privateKey, privateKey);
  });
});

describe("hosts and nonces", () => {
  it("derives the host a request is signed for from its url", () => {
    for (const [url, host] of [
      ["https://Example.com/auth", "example.com"],
      ["https://example.com:443", "example.com"],
      ["http://example.com:80/", "example.com"],
      ["http://example.com:8080", "example.com:8080"],
      ["http://10.0.0.5:9120", "10.0.0.5:9120"],
      ["http://[::1]:80", "[::1]"],
      ["http://[::1]:9120", "[::1]:9120"],
      ["wss://c.example.com/ws", "c.example.com"],
      [" https://example.com ", "example.com"],
      [new URL("https://example.com/x?y=1"), "example.com"],
    ]) {
      assert.equal(urlHost(url), host, String(url));
    }
    assert.throws(() => urlHost("ftp://example.com"), /not an http\(s\) url/);
    assert.throws(() => urlHost("example.com"), /Invalid url/);
    assert.throws(() => urlHost("https://"), /Invalid url|no host/);
    // Credentials are refused, and never repeated.
    let e;
    try {
      urlHost("https://user:hunter2@example.com");
    } catch (error) {
      e = error;
    }
    assert.match(e.message, /carries credentials/);
    assert.ok(!e.message.includes("hunter2"));
  });

  it("takes the path and query as sent, without the fragment", () => {
    assert.equal(urlPathAndQuery("https://example.com"), "/");
    assert.equal(
      urlPathAndQuery("https://example.com/read?x=1#frag"),
      "/read?x=1",
    );
    assert.equal(urlPathAndQuery("https://example.com/a b"), "/a%20b");
  });

  it("validates hosts and nonces as the server does", () => {
    assert.ok(validHost("example.com"));
    assert.ok(validHost("[::1]:9120"));
    assert.ok(!validHost("Example.com"));
    assert.ok(!validHost(""));
    assert.ok(!validHost("a".repeat(261)));
    assert.ok(validNonce(NONCE));
    assert.ok(validNonce("a-b_c-d_e-f_g-h_"));
    assert.ok(!validNonce("tooshort"));
    assert.ok(!validNonce("a".repeat(65)));
    assert.ok(!validNonce(`${NONCE}!`));
    const nonce = randomNonce();
    assert.match(nonce, /^[0-9a-f]{32}$/);
    assert.notEqual(nonce, randomNonce());
  });
});

describe("signed request headers", () => {
  it("makes the five headers of a request made now, which verify", async () => {
    const keys = await signingKeys(VECTOR_PRIVATE);
    const before = Date.now();
    const headers = await signedRequestHeaders(
      keys,
      "example.com",
      "POST",
      "/read?x=1",
      VECTOR_BODY,
    );
    assert.deepEqual(Object.keys(headers).sort(), [
      API_HOST_HEADER,
      API_NONCE_HEADER,
      API_PUBLIC_KEY_HEADER,
      API_SIGNATURE_HEADER,
      API_TIMESTAMP_HEADER,
    ]);
    assert.equal(headers[API_PUBLIC_KEY_HEADER], VECTOR_PUBLIC);
    assert.equal(headers[API_HOST_HEADER], "example.com");
    const timestamp = Number(headers[API_TIMESTAMP_HEADER]);
    assert.ok(timestamp >= before && timestamp <= Date.now());
    assert.match(headers[API_TIMESTAMP_HEADER], /^\d+$/);
    assert.ok(validNonce(headers[API_NONCE_HEADER]));
    assert.equal(
      Buffer.from(headers[API_SIGNATURE_HEADER], "base64").length,
      64,
    );
    const message = await messageOf(headers, "POST", "/read?x=1", VECTOR_BODY);
    assert.ok(verifies(VECTOR_PUBLIC, message, headers[API_SIGNATURE_HEADER]));
    // Over nothing else.
    for (const [method, path, body] of [
      ["GET", "/read?x=1", VECTOR_BODY],
      ["POST", "/read", VECTOR_BODY],
      ["POST", "/read?x=1", "{}"],
    ]) {
      assert.ok(
        !verifies(
          VECTOR_PUBLIC,
          await messageOf(headers, method, path, body),
          headers[API_SIGNATURE_HEADER],
        ),
      );
    }
    // A new nonce every call.
    const again = await signedRequestHeaders(
      keys,
      "example.com",
      "POST",
      "/read?x=1",
      VECTOR_BODY,
    );
    assert.notEqual(again[API_NONCE_HEADER], headers[API_NONCE_HEADER]);
    assert.notEqual(again[API_SIGNATURE_HEADER], headers[API_SIGNATURE_HEADER]);
  });

  it("signs for the host and path of a url", async () => {
    const keys = await signingKeys(VECTOR_PRIVATE);
    const headers = await signedRequestHeadersForUrl(
      keys,
      "POST",
      "https://Example.com:443/read?x=1#frag",
      "",
    );
    assert.equal(headers[API_HOST_HEADER], "example.com");
    assert.ok(
      verifies(
        VECTOR_PUBLIC,
        await messageOf(headers, "POST", "/read?x=1", ""),
        headers[API_SIGNATURE_HEADER],
      ),
    );
    await assert.rejects(
      signedRequestHeadersForUrl(
        keys,
        "POST",
        "https://u:p@example.com/read",
        "",
      ),
      /carries credentials/,
    );
  });

  it("signs the path after an address, the one the server receives", async () => {
    const sign = requestSigner(signingKeys(VECTOR_PRIVATE), {
      address: "https://example.com/app/",
      headers: { "x-api-type": "Device", [API_HOST_HEADER]: "ignored" },
    });
    const headers = await sign({
      method: "POST",
      url: "https://example.com/app/read?x=1",
      body: VECTOR_BODY,
    });
    assert.equal(headers["x-api-type"], "Device");
    // The signed headers win over the extra ones.
    assert.equal(headers[API_HOST_HEADER], "example.com");
    assert.ok(
      verifies(
        VECTOR_PUBLIC,
        await messageOf(headers, "POST", "/read?x=1", VECTOR_BODY),
        headers[API_SIGNATURE_HEADER],
      ),
    );
    // The address itself is `/`; a request without a body signs the
    // empty one.
    const root = await sign({ method: "GET", url: "https://example.com/app" });
    assert.ok(
      verifies(
        VECTOR_PUBLIC,
        await messageOf(root, "GET", "/", ""),
        root[API_SIGNATURE_HEADER],
      ),
    );
    await assert.rejects(
      sign({ method: "POST", url: "https://example.com/other/read" }),
      /not under the address/,
    );
    await assert.rejects(
      sign({ method: "POST", url: "https://example.com/approved" }),
      /not under the address/,
    );
  });

  it("signs for a configured host, and for the url's by default", async () => {
    const keys = await signingKeys(VECTOR_PRIVATE);
    const byUrl = await requestSigner(keys)({
      method: "POST",
      url: "https://Example.com/read",
      body: "{}",
    });
    assert.equal(byUrl[API_HOST_HEADER], "example.com");
    const tunneled = await requestSigner(keys, { host: "core.internal:9120" })({
      method: "POST",
      url: "http://127.0.0.1:9120/read",
      body: "{}",
    });
    assert.equal(tunneled[API_HOST_HEADER], "core.internal:9120");
    assert.ok(
      verifies(
        VECTOR_PUBLIC,
        await messageOf(tunneled, "POST", "/read", "{}"),
        tunneled[API_SIGNATURE_HEADER],
      ),
    );
  });

  it("rejects every request with the reason a key doesn't parse", async () => {
    const sign = requestSigner(
      signingKeys("not a key, and longer than thirty-two bytes"),
    );
    for (let i = 0; i < 2; i++) {
      await assert.rejects(
        sign({ method: "POST", url: "https://example.com/read", body: "{}" }),
        /32 characters or less, or pkcs8/,
      );
    }
  });
});

describe("fetchSignedJson", () => {
  const sign = requestSigner(signingKeys(VECTOR_PRIVATE), {
    headers: { "x-api-type": "User" },
  });
  const init = {
    method: "post",
    body: VECTOR_BODY,
    headers: { "content-type": "application/json", "X-Trace": "t" },
  };

  it("sends the request signed, without redirects or cookies", async () => {
    mockFetch(Response.json({ ok: true }));
    assert.deepEqual(
      await fetchSignedJson("https://example.com/read?x=1", init, sign),
      { ok: true },
    );
    assert.equal(sent.length, 1);
    const [{ input, init: sentInit }] = sent;
    assert.equal(input, "https://example.com/read?x=1");
    // `fetch` sends `post` as `POST`: signed as sent.
    assert.equal(sentInit.method, "POST");
    assert.equal(sentInit.body, VECTOR_BODY);
    assert.equal(sentInit.redirect, "error");
    assert.equal(sentInit.credentials, "omit");
    const { headers } = sentInit;
    assert.equal(headers["content-type"], "application/json");
    assert.equal(headers["x-trace"], "t");
    assert.equal(headers["x-api-type"], "User");
    assert.equal(headers[API_PUBLIC_KEY_HEADER], VECTOR_PUBLIC);
    assert.ok(
      verifies(
        VECTOR_PUBLIC,
        await messageOf(headers, "POST", "/read?x=1", VECTOR_BODY),
        headers[API_SIGNATURE_HEADER],
      ),
    );
  });

  it("keeps a redirect or cookie policy of its own", async () => {
    mockFetch(Response.json({}));
    await fetchSignedJson(
      "https://example.com/read",
      { ...init, redirect: "follow", credentials: "include" },
      sign,
    );
    assert.equal(sent[0].init.redirect, "follow");
    assert.equal(sent[0].init.credentials, "include");
  });

  it("sends a request without a body signed over the empty one", async () => {
    mockFetch(Response.json({}));
    await fetchSignedJson("https://example.com/user", { method: "GET" }, sign);
    const { headers } = sent[0].init;
    assert.equal(sent[0].init.body, undefined);
    assert.ok(
      verifies(
        VECTOR_PUBLIC,
        await messageOf(headers, "GET", "/user", ""),
        headers[API_SIGNATURE_HEADER],
      ),
    );
  });

  it("sends the request once more, signed anew, when its timestamp was refused", async () => {
    const refusal = Response.json(
      { error: `${SIGNED_AT_ANOTHER_TIME}: 1718000000000`, trace: [] },
      { status: 401 },
    );
    mockFetch(
      refusal,
      new Response(null, { status: 200 }),
      Response.json({ ok: true }),
    );
    assert.deepEqual(
      await fetchSignedJson("https://example.com/read", init, sign),
      { ok: true },
    );
    assert.equal(sent.length, 3);
    const [first, head, second] = sent;
    assert.equal(head.init.method, "HEAD");
    assert.equal(head.init.redirect, "error");
    assert.equal(head.init.credentials, "omit");
    assert.equal(second.init.method, "POST");
    assert.equal(second.init.body, VECTOR_BODY);
    assert.notEqual(
      second.init.headers[API_NONCE_HEADER],
      first.init.headers[API_NONCE_HEADER],
    );
    assert.ok(
      verifies(
        VECTOR_PUBLIC,
        await messageOf(second.init.headers, "POST", "/read", VECTOR_BODY),
        second.init.headers[API_SIGNATURE_HEADER],
      ),
    );
  });

  it("takes a second refusal, and any other 401, as the answer", async () => {
    const refused = { error: `${SIGNED_AT_ANOTHER_TIME}: 1`, trace: [] };
    mockFetch(
      Response.json(refused, { status: 401 }),
      () => {
        throw new TypeError("fetch failed");
      },
      Response.json(refused, { status: 401 }),
    );
    let e = await rejection(
      fetchSignedJson("https://example.com/read", init, sign),
    );
    assert.deepEqual(e, { status: 401, result: refused, server: true });
    assert.equal(sent.length, 3);

    const other = { error: "Invalid client credentials", trace: [] };
    mockFetch(Response.json(other, { status: 401 }));
    e = await rejection(
      fetchSignedJson("https://example.com/read", init, sign),
    );
    assert.deepEqual(e, { status: 401, result: other, server: true });
    assert.equal(sent.length, 1);
  });

  it("refuses other credentials, a body which isn't bytes, and a key which isn't one, sending nothing", async () => {
    mockFetch();
    for (const [url, extra] of [
      ["https://u:p@example.com/read", {}],
      ["https://example.com/read", { authorization: "jwt" }],
      ["https://example.com/read", { "X-API-KEY": "k" }],
      ["https://example.com/read", { "x-api-secret": "s" }],
    ]) {
      const e = await rejection(
        fetchSignedJson(
          url,
          { ...init, headers: { ...init.headers, ...extra } },
          sign,
        ),
      );
      assert.equal(e.status, 1);
      assert.equal(e.result.trace[0], `Error: ${OTHER_CREDENTIALS}`);
    }
    let e = await rejection(
      fetchSignedJson(
        "https://example.com/read",
        { ...init, body: new FormData() },
        sign,
      ),
    );
    assert.equal(e.status, 1);
    assert.match(e.result.trace[0], /string or bytes/);
    e = await rejection(
      fetchSignedJson(
        "https://example.com/read",
        init,
        requestSigner(signingKeys("file:/etc/key")),
      ),
    );
    assert.equal(e.status, 1);
    assert.match(e.result.trace[0], /looks like a file path/);
    assert.equal(sent.length, 0);
  });

  it("reports a network failure like fetchJson", async () => {
    mockFetch(() => {
      throw new TypeError("fetch failed", { cause: new Error("ECONNREFUSED") });
    });
    const e = await rejection(
      fetchSignedJson("https://example.com/read", init, sign),
    );
    assert.equal(e.status, 1);
    assert.deepEqual(e.result.trace, [
      "TypeError: fetch failed",
      "Error: ECONNREFUSED",
    ]);
  });
});

describe("MoghAuthClient with a signing key", () => {
  it("signs its manage requests, and has no static headers", async () => {
    const credential = { sign: requestSigner(signingKeys(VECTOR_PRIVATE)) };
    assert.deepEqual(credentialHeaders(credential), {});
    assert.equal(credentialSigner(credential), credential.sign);
    assert.equal(credentialSigner({ key: "k", secret: "s" }), undefined);
    assert.equal(credentialSigner("jwt"), undefined);
    assert.equal(credentialSigner(undefined), undefined);

    mockFetch(Response.json({ user_id: "u" }));
    const auth = MoghAuthClient("https://example.com/auth", credential);
    assert.deepEqual(await auth.manage("GetUserId", {}), { user_id: "u" });
    const [{ input, init }] = sent;
    assert.equal(input, "https://example.com/auth/manage/GetUserId");
    assert.equal(init.credentials, "omit");
    assert.equal(init.redirect, "error");
    assert.equal(init.headers["content-type"], "application/json");
    assert.equal(init.headers.authorization, undefined);
    assert.ok(
      verifies(
        VECTOR_PUBLIC,
        await messageOf(
          init.headers,
          "POST",
          "/auth/manage/GetUserId",
          init.body,
        ),
        init.headers[API_SIGNATURE_HEADER],
      ),
    );
  });
});
