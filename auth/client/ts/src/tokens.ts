import { jwtDecode } from "jwt-decode";

export const extractUserIdFromJwt = (jwt: string) => {
  return jwtDecode<{ sub: string | undefined }>(jwt).sub;
};

type LoginTokens = {
  /** Current User ID */
  current: string | undefined;
  /** Array of logged in user ids / tokens */
  tokens: Array<{ user_id: string; jwt: string }>;
};

const LOGIN_TOKENS_KEY = "mogh-auth-tokens-v1";

export const LOGIN_TOKENS = (() => {
  const stored = localStorage.getItem(LOGIN_TOKENS_KEY);

  let tokens: LoginTokens = stored
    ? JSON.parse(stored)
    : { current: undefined, tokens: [] };

  const update_local_storage = () => {
    localStorage.setItem(LOGIN_TOKENS_KEY, JSON.stringify(tokens));
  };

  const accounts = () => {
    const current = tokens.tokens.find((t) => t.user_id === tokens.current);
    const filtered = tokens.tokens.filter((t) => t.user_id !== tokens.current);
    return current ? [current, ...filtered] : filtered;
  };

  const add_and_change = (jwt: string) => {
    const user_id = extractUserIdFromJwt(jwt);
    if (!user_id) return;
    const filtered = tokens.tokens.filter((t) => t.user_id !== user_id);
    filtered.push({ user_id, jwt });
    filtered.sort();
    tokens = {
      current: user_id,
      tokens: filtered,
    };
    update_local_storage();
  };

  const remove = (user_id: string) => {
    const filtered = tokens.tokens.filter((t) => t.user_id !== user_id);
    tokens = {
      current:
        tokens.current === user_id ? filtered[0]?.user_id : tokens.current,
      tokens: filtered,
    };
    update_local_storage();
  };

  const remove_all = () => {
    tokens = {
      current: undefined,
      tokens: [],
    };
    update_local_storage();
  };

  const change = (to_id: string) => {
    tokens = {
      current: to_id,
      tokens: tokens.tokens,
    };
    update_local_storage();
  };

  return {
    jwt: () =>
      tokens.current
        ? tokens.tokens.find((t) => t.user_id === tokens.current)?.jwt ?? ""
        : "",
    accounts,
    add_and_change,
    remove,
    remove_all,
    change,
  };
})();
