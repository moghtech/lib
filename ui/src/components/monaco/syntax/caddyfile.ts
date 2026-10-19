import * as monaco from "monaco-editor";

// Caddyfile (Caddy 2), and Corefile (CoreDNS: the same syntax, without
// matchers).
//
// Monarch tokenizes a line at a time, matching each rule against the
// rest of the line, so what a token means by its place on the line is
// carried in the state:
//
// - `root`: outside the blocks. A line's first token is a site address
//   (then `addresses`), the `{` of the global options, a `(snippet)`,
//   a `&(named route)` or an `import`.
// - `addresses`: the rest of a site's address line. Its `{` opens the
//   site block; a `,` or `\` ending the line continues the addresses
//   on the next one (`addresses_cont`); a line ending in neither is a
//   site without braces, whose directives are the lines after it
//   (`braceless`).
// - `block`: the directives of a site block, snippet, `handle { }`, ...
//   whose first argument can be a matcher. `subblock`: a directive's
//   own block, of subdirectives (no matcher). `braceless`: `block` for
//   the one site without braces (`}` is invalid).
// - `line.<directive>`: the rest of a directive's line, popped at the
//   start of the next line. Its `{` opens a `block` after the
//   directives whose blocks hold directives (`@containers`), else a
//   `subblock`; a `\` ending the line continues the directive on the
//   next one (`cont.<directive>`).
// - `string`, `raw`, `heredoc.<MARKER>`: inside `"..."`, `` `...` ``
//   and `<<MARKER` strings, which can all span lines.
//
// The start of a line is where `^` rules match, the end of one is the
// `@eos` guard: `addresses` and `cont` switch state on the token which
// ends the line, `line` and `addresses_cont` at the start of the next.
//
// Each rule consumes a run at once, so a line tokenizes in time linear
// in its length (tests/tokenizer_timing.test.ts).

type Rule = monaco.languages.IMonarchLanguageRule;
type Action = monaco.languages.IMonarchLanguageAction;

/**
 * A directive, subdirective, global option or matcher module: coloured
 * like the keys of the other languages.
 */
const DIRECTIVE = "key";
const ADDRESS = "entity.name.address";
const SNIPPET = "entity.name.snippet";
const ROUTE = "entity.name.route";
/** `@name`, `*` and `/path` matchers. */
const MATCHER = "entity.name.tag.matcher";
/** `{http.request.host}`, `{$ENV:default}`, `{args[0]}`, ... */
const PLACEHOLDER = "variable.placeholder";
const STRING = "string";
const HEREDOC = "string.heredoc";
const HEREDOC_MARKER = "string.heredoc.marker";

/** A regex from a template, whose `${}` hold regexes (or text) to inline. */
function rx(strings: TemplateStringsArray, ...parts: (RegExp | string)[]) {
  let source = "";
  strings.raw.forEach((text, i) => {
    source += text;
    const part = parts[i];
    if (part !== undefined) {
      source += typeof part === "string" ? part : part.source;
    }
  });
  return new RegExp(source);
}

/**
 * An unquoted token: up to whitespace or a placeholder. Only its first
 * character can't be a quote or `#`: `foo"bar` and `foo#bar` are one
 * token, as are `foo{` and `foo}`, since only a `{` / `}` on its own
 * opens or closes a block.
 */
const PLAIN = /[^\s{}"`#](?:[^\s{}]|\{(?![^{}\s]+\})|\})*/;
/** A placeholder: `{...}` without whitespace. */
const PLACEHOLDER_RE = /\{[^{}\s]+\}/;
/** A directive's name, as the `line.<name>` state carries it. */
const NAME = /[A-Za-z_][\w-]{0,63}/;
/** A matcher as a directive's first argument: `@name`, `/path`, `*`. */
const MATCHER_ARG = /(?:@[^\s{}]+|\/(?:[^\s{}]|\{[^{}\s]*\})*|\*)(?=\s|$)/;
/** Directives whose first argument is never a matcher. */
const NO_MATCHER = ["tls", "bind", "log", "import", "handle_errors"];
/** Directives whose block holds directives (with matchers), not subdirectives. */
const CONTAINERS = [
  "handle",
  "handle_path",
  "handle_errors",
  "handle_response",
  "route",
];

/** The rules, each switching to `state` when its match ends the line. */
function atEos(rules: [RegExp, string][], state: string): Rule[] {
  return rules.map(([regex, token]) => [
    regex,
    { cases: { "@eos": { token, switchTo: state }, "@default": token } },
  ]);
}

/**
 * The arguments of a directive: in its `line.<directive>` state, in
 * its `cont.<directive>` continuation line, or in a `block` line with
 * no directive (one starting with a string or placeholder).
 */
function argRules(ctx: "line" | "cont" | "block"): Rule[] {
  const open: Action =
    ctx === "block"
      ? { token: "@brackets", next: "@subblock" }
      : {
          cases: {
            "$S2@containers": { token: "@brackets", switchTo: "@block" },
            "@default": { token: "@brackets", switchTo: "@subblock" },
          },
        };
  const continued: Action =
    ctx === "line"
      ? { token: "", switchTo: "@cont.$S2" }
      : ctx === "cont"
        ? ""
        : { token: "", next: "@cont.none" };
  const tokens: [RegExp, string][] = [
    [/\s+/, ""],
    [/#.*$/, "comment"],
    [/\{\}/, ""],
    [PLACEHOLDER_RE, PLACEHOLDER],
    [/@[^\s{}]+/, MATCHER],
    // A number, with a decimal and units: `200`, `2.5s`, `1h30m`, `100mb`.
    // Each `[A-Za-z]+` run ends at digits or the token, so a run is
    // read one way (not exponentially many).
    [/\d+(?:\.\d+)?(?:[A-Za-zµ]+\d+)*[A-Za-zµ]*(?=\s|$)/, "number"],
    [PLAIN, ""],
    [/\{/, ""],
    [/\}/, "invalid"],
  ];
  return [
    // A `\` ending the line continues it on the next
    [/\\$/, continued],
    // A `{` on its own opens a block
    [/\{(?=\s|$)/, open],
    [/<<([A-Za-z0-9_-]+)$/, { token: HEREDOC_MARKER, next: "@heredoc.$1" }],
    [/"/, { token: STRING, next: "@string" }],
    [/`/, { token: STRING, next: "@raw" }],
    ...(ctx === "cont" ? atEos(tokens, "@line.$S2") : tokens),
  ];
}

/**
 * The lines of a block: directives, taking a matcher as their first
 * argument when `matchers`, or subdirectives. `close` is the action of
 * its `}`.
 */
function blockRules(opts: { matchers: boolean; close: Action }): Rule[] {
  const rules: Rule[] = [
    // A matcher definition: `@name module args...`, `@name {`
    [
      rx`^(\s*)(@[^\s{}]+)(\s+)(${PLAIN})`,
      ["", MATCHER, "", { token: DIRECTIVE, next: "@line.matcher" }],
    ],
    [/^(\s*)(@[^\s{}]+)/, ["", { token: MATCHER, next: "@line.matcher" }]],
  ];
  if (opts.matchers) {
    // A directive with a matcher as its first argument
    rules.push([
      rx`^(\s*)((?!(?:${NO_MATCHER.join("|")})(?:\s|$))${NAME})(\s+)(${MATCHER_ARG})`,
      ["", { token: DIRECTIVE, next: "@line.$2" }, "", MATCHER],
    ]);
  }
  rules.push(
    [rx`^(\s*)(${NAME})(?=\s|$)`, ["", { token: DIRECTIVE, next: "@line.$2" }]],
    // Any other first token is the line's directive too
    [rx`^(\s*)(${PLAIN})`, ["", { token: DIRECTIVE, next: "@line.none" }]],
    [/\}/, opts.close],
    ...argRules("block"),
  );
  return rules;
}

function language(opts: {
  postfix: string;
  matchers: boolean;
}): monaco.languages.IMonarchLanguage {
  const { matchers } = opts;
  const pop: Action = { token: "@brackets", next: "@pop" };
  return {
    defaultToken: "",
    tokenPostfix: opts.postfix,
    containers: matchers ? CONTAINERS : [],

    tokenizer: {
      root: [
        // An `import` of files of site blocks
        [
          /^(\s*)(import)(?=\s|$)/,
          ["", { token: DIRECTIVE, next: "@line.import" }],
        ],
        // `(snippet) {`, `&(route) {`
        [
          /^(\s*)(\()([^()\s]+)(\))/,
          [
            "",
            "@brackets",
            SNIPPET,
            { token: "@brackets", next: "@addresses" },
          ],
        ],
        [
          /^(\s*)(&)(\()([^()\s]+)(\))/,
          [
            "",
            "delimiter",
            "@brackets",
            ROUTE,
            { token: "@brackets", next: "@addresses" },
          ],
        ],
        // A site's address line, from before its first token
        [
          rx`^(?=\s*(?:[^\s{}#(&]|${PLACEHOLDER_RE}))`,
          { token: "", next: "@addresses" },
        ],
        [/\s+/, ""],
        [/#.*$/, "comment"],
        // The global options block
        [/\{(?=\s|$)/, { token: "@brackets", next: "@subblock" }],
        [/\}/, "invalid"],
        [/\S+/, ""],
      ],

      addresses: [
        [/\{(?=\s|$)/, { token: "@brackets", switchTo: "@block" }],
        // A `,` or `\` ending the line continues the addresses on the next
        [
          /,(?=\s*(?:#.*)?$)/,
          { token: "delimiter", switchTo: "@addresses_cont" },
        ],
        [/\\$/, { token: "", switchTo: "@addresses_cont" }],
        [/"/, { token: STRING, next: "@string" }],
        [/`/, { token: STRING, next: "@raw" }],
        // A line with no `{`: the site has no braces, its directives follow
        ...atEos(
          [
            [/\s+/, ""],
            [/#.*$/, "comment"],
            [/,/, "delimiter"],
            [PLACEHOLDER_RE, PLACEHOLDER],
            [/[^\s{},"`#][^\s{},]*/, ADDRESS],
            [/[{}]/, "invalid"],
          ],
          "@braceless",
        ),
      ],

      addresses_cont: [
        [/^/, { token: "", switchTo: "@addresses" }],
        [/\s+/, ""],
        [/#.*$/, "comment"],
      ],

      block: blockRules({ matchers, close: pop }),
      subblock: blockRules({ matchers: false, close: pop }),
      braceless: blockRules({ matchers, close: "invalid" }),

      line: [[/^/, { token: "", next: "@pop" }], ...argRules("line")],
      cont: argRules("cont"),

      string: [
        // An environment placeholder's default can hold whitespace
        [/\{\$[^{}]*\}/, PLACEHOLDER],
        [PLACEHOLDER_RE, PLACEHOLDER],
        // The only escape: a backslash before anything else is literal
        [/\\"/, "string.escape"],
        [/"/, { token: STRING, next: "@pop" }],
        [/[^"\\{]+/, STRING],
        [/[\\{]/, STRING],
      ],

      raw: [
        [PLACEHOLDER_RE, PLACEHOLDER],
        [/`/, { token: STRING, next: "@pop" }],
        [/[^`{]+/, STRING],
        [/\{/, STRING],
      ],

      heredoc: [
        // The closing marker, then the rest of the directive's arguments
        [/^(\s*)($S2)(?=\s|$)/, ["", { token: HEREDOC_MARKER, next: "@pop" }]],
        [PLACEHOLDER_RE, PLACEHOLDER],
        [/[^{]+/, HEREDOC],
        [/\{/, HEREDOC],
      ],
    },
  };
}

export const caddyfile_conf: monaco.languages.LanguageConfiguration = {
  comments: { lineComment: "#" },
  brackets: [
    ["{", "}"],
    ["(", ")"],
  ],
  autoClosingPairs: [
    { open: "{", close: "}" },
    { open: "(", close: ")" },
    { open: '"', close: '"', notIn: ["string"] },
    { open: "`", close: "`", notIn: ["string"] },
  ],
  surroundingPairs: [
    { open: "{", close: "}" },
    { open: "(", close: ")" },
    { open: '"', close: '"' },
    { open: "`", close: "`" },
  ],
};

export const caddyfile_language = language({
  postfix: ".caddyfile",
  matchers: true,
});

/** CoreDNS: a Caddyfile without matchers (`file /path` is a path). */
export const corefile_language = language({
  postfix: ".corefile",
  matchers: false,
});

monaco.languages.register({ id: "caddyfile" });
monaco.languages.setLanguageConfiguration("caddyfile", caddyfile_conf);
monaco.languages.setMonarchTokensProvider("caddyfile", caddyfile_language);

monaco.languages.register({ id: "corefile" });
monaco.languages.setLanguageConfiguration("corefile", caddyfile_conf);
monaco.languages.setMonarchTokensProvider("corefile", corefile_language);
