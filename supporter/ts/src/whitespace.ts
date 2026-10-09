/**
 * Whitespace as the Rust crate has it: the Unicode `White_Space`
 * property of `char::is_whitespace` and `str::trim`. JavaScript's `\s`
 * and `trim()` also take U+FEFF (a byte order mark) for whitespace and
 * leave U+0085 (NEL), so they would trim, or refuse, what the server
 * doesn't.
 */
const SURROUNDING_WHITESPACE = /^\p{White_Space}+|\p{White_Space}+$/gu;

/** `text` without leading and trailing whitespace, like Rust's `str::trim`. */
export function trimWhitespace(text: string): string {
  return text.replace(SURROUNDING_WHITESPACE, "");
}
