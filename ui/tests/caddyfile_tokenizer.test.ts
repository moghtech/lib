import { test } from "node:test";
import assert from "node:assert/strict";
import { loadSyntax, tokenizer, type Token } from "./monarch.ts";

// The real `caddyfile` / `corefile` definitions, through Monaco's own
// Monarch compiler and tokenizer (see ./monarch.ts).
await loadSyntax("caddyfile");

/**
 * The types of a line's tokens which aren't only whitespace, in order,
 * without the language postfix. Monaco merges neighbouring tokens of
 * one type, so `app:9000 app2:9000` is one `""` token.
 */
function types(tokens: Token[], line: string, postfix: string) {
  return tokens
    .filter((token, i) => {
      const end = tokens[i + 1]?.offset ?? line.length;
      return line.slice(token.offset, end).trim() !== "";
    })
    .map(({ type }) => {
      if (type.endsWith(postfix)) return type.slice(0, -postfix.length);
      // Bracket tokens have no postfix
      assert.ok(type === "" || type.startsWith("delimiter."), type);
      return type;
    });
}

/** Tokenizes a document line by line, checking each line's token types. */
function check(language: string, document: [string, string[]][]) {
  const tokenize = tokenizer(language);
  for (const [line, expected] of document) {
    let tokens: Token[];
    try {
      tokens = tokenize(line);
    } catch (error) {
      assert.fail(`${JSON.stringify(line)}: ${error}`);
    }
    assert.deepEqual(
      types(tokens, line, `.${language}`),
      expected,
      JSON.stringify(line),
    );
  }
}

const KEY = "key";
const ADDRESS = "entity.name.address";
const MATCHER = "entity.name.tag.matcher";
const PLACEHOLDER = "variable.placeholder";
const OPEN = "delimiter.curly";
const CLOSE = "delimiter.curly";
const PAREN = "delimiter.parenthesis";

test("caddyfile tokenizes global options, snippets, routes, sites, directives", () => {
  check("caddyfile", [
    ["# Global options", ["comment"]],
    ["{", [OPEN]],
    ["\temail admin@example.com", [KEY, ""]],
    ["\tservers {", [KEY, OPEN]],
    ["\t\tprotocols h1 h2", [KEY, ""]],
    ["\t}", [CLOSE]],
    ["}", [CLOSE]],
    ["", []],
    ["(common) {", [PAREN, "entity.name.snippet", PAREN, OPEN]],
    ["\tencode gzip zstd", [KEY, ""]],
    ["\theader -Server", [KEY, ""]],
    ["}", [CLOSE]],
    ["&(api) {", ["delimiter", PAREN, "entity.name.route", PAREN, OPEN]],
    ["\treverse_proxy app:9000", [KEY, ""]],
    ["}", [CLOSE]],
    ["import /etc/caddy/sites/*.caddy", [KEY, ""]],
    [
      "example.com, www.example.com { # the site",
      [ADDRESS, "delimiter", ADDRESS, OPEN, "comment"],
    ],
    ["\timport common", [KEY, ""]],
    ["\t@api path /api/*", [MATCHER, KEY, ""]],
    ["\thandle @api {", [KEY, MATCHER, OPEN]],
    // A directive's block holds subdirectives, whose first argument
    // isn't a matcher
    ["\t\treverse_proxy @api app:9000 {", [KEY, MATCHER, "", OPEN]],
    ["\t\t\theader_up Host {upstream_hostport}", [KEY, "", PLACEHOLDER]],
    ["\t\t\tflush_interval 1h30m", [KEY, "number"]],
    ["\t\t\tto /run/app.sock", [KEY, ""]],
    ["\t\t}", [CLOSE]],
    ["\t}", [CLOSE]],
    ["\troot * /var/www", [KEY, MATCHER, ""]],
    // tls takes no matcher: its files aren't one
    ["\ttls /etc/ssl/cert.pem /etc/ssl/key.pem", [KEY, ""]],
    ["\tbind 10.0.0.1", [KEY, ""]],
    [
      '\trespond /health "ok {http.request.host}" 200',
      [KEY, MATCHER, "string", PLACEHOLDER, "string", "number"],
    ],
    ["\trespond <<HTML", [KEY, "string.heredoc.marker"]],
    [
      "\t\t<p>{$GREETING:hi}</p>",
      ["string.heredoc", PLACEHOLDER, "string.heredoc"],
    ],
    ["\t\tHTML 200", ["string.heredoc.marker", "number"]],
    // A `\` continues the directive: the next line starts with an
    // argument, not a directive
    ["\treverse_proxy \\", [KEY, ""]],
    ["\t\tapp1:9000 \\", [""]],
    ["\t\tapp2:9000", [""]],
    ["\tlog {", [KEY, OPEN]],
    ["\t\toutput file /var/log/access.log {", [KEY, "", OPEN]],
    ["\t\t\troll_size 100mb", [KEY, "number"]],
    ["\t\t}", [CLOSE]],
    ["\t}", [CLOSE]],
    ["\thandle_path /static/* {", [KEY, MATCHER, OPEN]],
    ["\t\tfile_server", [KEY]],
    ["\t}", [CLOSE]],
    ["\tredir /old /new permanent", [KEY, MATCHER, ""]],
    ["\tbasic_auth { # auth", [KEY, OPEN, "comment"]],
    ["\t\tbob $2a$14$abc", [KEY, ""]],
    ["\t}", [CLOSE]],
    [
      "\theader +Via `{http.request.host}`",
      [KEY, "", "string", PLACEHOLDER, "string"],
    ],
    [
      '\trespond "say \\"hi\\""',
      [KEY, "string", "string.escape", "string", "string.escape", "string"],
    ],
    ["\tfile_server # comment", [KEY, "comment"]],
    ["}", [CLOSE]],
    ["{$DOMAIN}:8443 {", [PLACEHOLDER, ADDRESS, OPEN]],
    ["\ttls internal", [KEY, ""]],
    ["}", [CLOSE]],
  ]);
});

test("caddyfile tokenizes the one site without braces", () => {
  check("caddyfile", [
    ["localhost", [ADDRESS]],
    ["", []],
    ["reverse_proxy /api/* localhost:9001", [KEY, MATCHER, ""]],
    ["file_server", [KEY]],
    ["}", ["invalid"]],
  ]);
});

test("caddyfile tokenizes addresses continued on the next line", () => {
  check("caddyfile", [
    ["example.com,", [ADDRESS, "delimiter"]],
    ["www.example.com, # more", [ADDRESS, "delimiter", "comment"]],
    ["", []],
    ["api.example.com {", [ADDRESS, OPEN]],
    ["\trespond 200", [KEY, "number"]],
    ["}", [CLOSE]],
    ["}", ["invalid"]],
  ]);
});

test("caddyfile strings span lines", () => {
  check("caddyfile", [
    ["example.com {", [ADDRESS, OPEN]],
    ['\trespond "two', [KEY, "string"]],
    ['lines" 200', ["string", "number"]],
    ["\tfile_server", [KEY]],
    ["\trespond 200 }", [KEY, "number", "invalid"]],
    ["}", [CLOSE]],
  ]);
});

test("corefile tokenizes server blocks and plugins, without matchers", () => {
  check("corefile", [
    [".:53 {", [ADDRESS, OPEN]],
    ["\tforward . 8.8.8.8", [KEY, ""]],
    ["\tfile /etc/coredns/db.example.org example.org", [KEY, ""]],
    ["\tcache 30", [KEY, "number"]],
    ["\tlog", [KEY]],
    ["\thosts {", [KEY, OPEN]],
    ["\t\t10.0.0.1 host.local", [KEY, ""]],
    ["\t\tfallthrough", [KEY]],
    ["\t}", [CLOSE]],
    ["}", [CLOSE]],
    ["example.org:1053 {", [ADDRESS, OPEN]],
    ["\troot /var/lib/coredns", [KEY, ""]],
    ["\thandle_path /x/* {", [KEY, "", OPEN]],
    ["\t\troot * /x", [KEY, ""]],
    ["\t}", [CLOSE]],
    ["\timport {$SNIPPET}", [KEY, PLACEHOLDER]],
    ["}", [CLOSE]],
  ]);
});
