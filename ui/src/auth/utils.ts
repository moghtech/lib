export function sanitizeQuery() {
  sanitizeQueryInner(new URLSearchParams(location.search));
}

export function sanitizeQueryInner(search: URLSearchParams) {
  search.delete("redeem_ready");
  search.delete("totp");
  search.delete("passkey");
  const query = search.toString();
  location.replace(
    `${location.origin}${location.pathname}${query.length ? "?" + query : ""}`,
  );
}
