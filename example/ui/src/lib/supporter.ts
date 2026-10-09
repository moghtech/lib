import type { RootKeys } from "mogh_supporter";

/**
 * The app the supporter key is for. The example plays `komodo`: the
 * key of mogh_supporter's fixture, which the server tests configure,
 * is for it. An app passes its own name.
 */
export const SUPPORTER_APP = "komodo";

/**
 * The release date of this build, never the current date: the
 * `releaseDate` of package.json, which vite.config.ts defines with
 * `mogh_supporter/vite`.
 */
export const RELEASE_DATE: string = __RELEASE_DATE__;

/**
 * The root keys supporter keys are verified under, hardcoded like an
 * app hardcodes its own root keys of mogh.tech (the same ones as its
 * server, `supporter_root_keys` in `server/src/auth.rs`). The example
 * is no release: it trusts the test root of mogh_supporter's fixture,
 * which a release must never.
 */
export const SUPPORTER_ROOT_KEYS: RootKeys = Object.freeze([
  // The test root, with the id fe812c12f3ab4ce6.
  "MCowBQYDK2VwAyEA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=",
]);
