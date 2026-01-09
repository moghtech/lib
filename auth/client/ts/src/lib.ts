import { LoginResponses, ManageResponses } from "./responses.js";
import type {
  ExternalLoginProvider,
  LoginRequest,
  ManageRequest,
} from "./types.js";

export * as Types from "./types.js";
export * as Passkey from "./passkey.js";
export { LOGIN_TOKENS, extractUserIdFromJwt } from "./tokens.js";
export type { LoginResponses, ManageResponses };

export function MoghAuthClient(url: string, jwt?: string) {
  const request = <Params, Res>(
    path: "/login" | "/manage",
    type: string,
    params: Params
  ): Promise<Res> =>
    new Promise(async (res, rej) => {
      try {
        let response = await fetch(`${url}${path}/${type}`, {
          method: "POST",
          body: JSON.stringify(params),
          headers: {
            "content-type": "application/json",
            ...(jwt ? { authorization: jwt } : {}),
          },
          credentials: "include",
        });
        if (response.status === 200) {
          const body: Res = await response.json();
          res(body);
        } else {
          try {
            const result = await response.json();
            rej({ status: response.status, result });
          } catch (error) {
            rej({
              status: response.status,
              result: {
                error: "Failed to get response body",
                trace: [JSON.stringify(error)],
              },
              error,
            });
          }
        }
      } catch (error) {
        rej({
          status: 1,
          result: {
            error: "Request failed with error",
            trace: [JSON.stringify(error)],
          },
          error,
        });
      }
    });

  const login = async <
    T extends LoginRequest["type"],
    Req extends Extract<LoginRequest, { type: T }>
  >(
    type: T,
    params: Req["params"]
  ) =>
    await request<Req["params"], LoginResponses[Req["type"]]>(
      "/login",
      type,
      params
    );

  const manage = async <
    T extends ManageRequest["type"],
    Req extends Extract<ManageRequest, { type: T }>
  >(
    type: T,
    params: Req["params"]
  ) =>
    await request<Req["params"], ManageResponses[Req["type"]]>(
      "/manage",
      type,
      params
    );

  const externalLogin = (provider: ExternalLoginProvider) => {
    const _redirect = location.pathname.startsWith("/login")
      ? location.origin +
        (new URLSearchParams(location.search).get("backto") ?? "")
      : location.href;
    const redirect = encodeURIComponent(_redirect);
    location.replace(
      `${url}/${provider.toLowerCase()}/login?redirect=${redirect}`
    );
  };

  return {
    login,
    manage,
    externalLogin,
  };
}
