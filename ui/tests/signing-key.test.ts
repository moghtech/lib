import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ED25519_SPKI_PREFIX,
  X25519_SPKI_PREFIX,
  isPrivateKey,
  publicKeyError,
  publicKeyExcerpt,
  publicKeyHints,
  publicKeyValue,
} from "../src/signing-key.ts";

// An Ed25519 public key, as Core stores it (base64 SPKI der).
const ED25519 = `${ED25519_SPKI_PREFIX}tLW1qqzwMQfJGAu7hnf8vfl6XwiLv1ngfDcLHeInGHE=`;
const PEM = `-----BEGIN PUBLIC KEY-----\n${ED25519}\n-----END PUBLIC KEY-----\n`;
// A pkcs8 Ed25519 private key (base64 der), what CreateSigningKey returns.
const PRIVATE_DER =
  "MC4CAQAwBQYDK2VwBCIEIHv+2sRufwLq0xJwfKqDxg5jq4Z0dM6K2dG0pdh0PLhj";

test("public key excerpts skip the shared header", () => {
  assert.equal(publicKeyExcerpt(ED25519), "…tLW1qqzwMQfJ…");
  assert.equal(publicKeyExcerpt(ED25519, 4), "…tLW1…");
  // A key of another algorithm keeps its header, and so stands apart.
  assert.equal(
    publicKeyExcerpt(`${X25519_SPKI_PREFIX}abcdefghijklmnop`),
    "MCowBQYDK2Vu…",
  );
  assert.equal(publicKeyExcerpt("short"), "short");
});

test("private keys are told apart from public keys", () => {
  assert.equal(isPrivateKey(PRIVATE_DER), true);
  assert.equal(isPrivateKey("-----BEGIN PRIVATE KEY-----\nx\n-----END"), true);
  assert.equal(isPrivateKey(ED25519), false);
  assert.equal(isPrivateKey(PEM), false);
  assert.equal(isPrivateKey("not base64!"), false);
});

test("a pasted public key is sent as its base64 spki", () => {
  assert.equal(publicKeyValue(ED25519), ED25519);
  assert.equal(publicKeyValue(`  ${ED25519}\n`), ED25519);
  assert.equal(publicKeyValue(PEM), ED25519);
  // A pem whose line breaks were lost.
  assert.equal(publicKeyValue(PEM.replaceAll("\n", " ")), ED25519);
});

test("the form refuses what can't be an Ed25519 public key", () => {
  assert.equal(publicKeyError(""), null);
  assert.equal(publicKeyError(ED25519), null);
  assert.equal(publicKeyError(PEM), null);
  assert.match(publicKeyError(PRIVATE_DER)!, /private key/);
  assert.match(
    publicKeyError("-----BEGIN CERTIFICATE-----")!,
    /PEM PUBLIC KEY/,
  );
  assert.match(
    publicKeyError(`${X25519_SPKI_PREFIX}abcdefghijklmnop`)!,
    /X25519/,
  );
  assert.match(publicKeyError("MCowBQYDK2VwAyEB")!, /Not an Ed25519/);
  assert.match(publicKeyError("hunter2")!, /Not an Ed25519/);
});

test("the hints name the app's key file", () => {
  const hints = publicKeyHints("komodo.key");
  assert.match(hints.privateKey, /openssl pkey -in komodo\.key -pubout/);
  assert.match(hints.x25519, /-out komodo\.key/);
  assert.equal(publicKeyError(PRIVATE_DER, hints), hints.privateKey);
  assert.equal(
    publicKeyError(`${X25519_SPKI_PREFIX}abcdefghijklmnop`, hints),
    hints.x25519,
  );
});

// Real pairs (the Ed25519 one is the example key of RFC 8410), for
// the cases an app's own forms rely on: Cicada kept these in its copy
// of the helpers until it moved to this module.
const RFC_PRIVATE =
  "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC";
const RFC_PUBLIC =
  "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
const RFC_PRIVATE_PEM = `-----BEGIN PRIVATE KEY-----\n${RFC_PRIVATE}\n-----END PRIVATE KEY-----`;
const RFC_PUBLIC_PEM = `-----BEGIN PUBLIC KEY-----\n${RFC_PUBLIC}\n-----END PUBLIC KEY-----\n`;
const X25519_PRIVATE =
  "MC4CAQAwBQYDK2VuBCIEIP8bd52uKstjL1QZat+i5Y/aABuKKexAWH2sPRlzXvsA";
const X25519_PUBLIC =
  "MCowBQYDK2VuAyEAwRo9XrP09PWCyhRx4XU6CTS25fUbwYrhYRDHVidVOnw=";
const X25519_PUBLIC_PEM = `-----BEGIN PUBLIC KEY-----\n${X25519_PUBLIC}\n-----END PUBLIC KEY-----\n`;

test("excerpts of real keys", () => {
  assert.equal(publicKeyExcerpt(RFC_PUBLIC), "…Gb9ECWmEzf6F…");
  assert.equal(publicKeyExcerpt("abcdefghijklmnop"), "abcdefghijkl…");
  assert.equal(publicKeyExcerpt(X25519_PUBLIC), "MCowBQYDK2Vu…");
});

test("a private key is known in base64 and PEM, of either algorithm", () => {
  assert.equal(isPrivateKey(RFC_PRIVATE), true);
  assert.equal(isPrivateKey(` ${RFC_PRIVATE}\n`), true);
  assert.equal(isPrivateKey(RFC_PRIVATE_PEM), true);
  assert.equal(isPrivateKey(X25519_PRIVATE), true);
  assert.equal(
    isPrivateKey("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END"),
    true,
  );
  assert.equal(isPrivateKey(RFC_PUBLIC), false);
  assert.equal(isPrivateKey(RFC_PUBLIC_PEM), false);
  assert.equal(isPrivateKey(X25519_PUBLIC), false);
  assert.equal(isPrivateKey(""), false);
});

test("the value sent is the base64 spki, whatever surrounds it", () => {
  assert.equal(publicKeyValue(RFC_PUBLIC_PEM), RFC_PUBLIC);
  assert.equal(publicKeyValue(`\n${RFC_PUBLIC_PEM}\n`), RFC_PUBLIC);
  assert.equal(publicKeyValue(""), "");
});

test("the form lets an Ed25519 public key through, and an empty value", () => {
  assert.equal(publicKeyError("  \n"), null);
  assert.equal(publicKeyError(RFC_PUBLIC), null);
  assert.equal(publicKeyError(` ${RFC_PUBLIC} `), null);
  assert.equal(publicKeyError(RFC_PUBLIC_PEM), null);
});

test("the form refuses a private key in every form", () => {
  for (const key of [RFC_PRIVATE, RFC_PRIVATE_PEM, X25519_PRIVATE]) {
    assert.match(publicKeyError(key)!, /^This is a private key/);
  }
});

test("the form tells an X25519 public key in every form", () => {
  const message = /^This is an X25519 key: signing keys are Ed25519 keys/;
  assert.match(publicKeyError(X25519_PUBLIC)!, message);
  assert.match(publicKeyError(` ${X25519_PUBLIC}\n`)!, message);
  assert.match(publicKeyError(X25519_PUBLIC_PEM)!, message);
  // A PEM whose line breaks were lost on paste.
  assert.match(publicKeyError(X25519_PUBLIC_PEM.replace(/\n/g, ""))!, message);
});

test("the form refuses a PEM of another key, and what is no key", () => {
  const rsa =
    "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK\n-----END PUBLIC KEY-----";
  assert.match(publicKeyError(rsa)!, /^Not an Ed25519 public key/);
  assert.match(
    publicKeyError("-----BEGIN PUBLIC KEY-----")!,
    /^Not an Ed25519 public key/,
  );
  // 60 characters which are no key.
  assert.match(publicKeyError("a".repeat(60))!, /^Not an Ed25519 public key/);
  assert.equal(
    publicKeyError("-----BEGIN CERTIFICATE-----\nAAAA\n-----END"),
    "Expected a PEM PUBLIC KEY",
  );
});
