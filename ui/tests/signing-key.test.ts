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
