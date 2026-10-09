import {
  credentialHeaders,
  fetchJson,
  type RequestError,
} from "mogh_auth_client";
import type {
  SupporterReadResponses,
  SupporterWriteResponses,
} from "./responses.ts";
import type {
  SupporterReadRequest,
  SupporterWriteRequest,
} from "./types.ts";

/**
 * A failed request, as the promises of `MoghSupporterClient` reject:
 * `mogh_auth_client`'s, whose `fetchJson` sends the requests. A UI
 * handles the failures of supporter, auth and app requests alike.
 */
export type { RequestError };

/**
 * The client of the supporter api an app serves (`mogh_supporter`'s
 * `server::router`, mounted at `url`, eg. `https://app.example/supporter`).
 * Requests are authenticated with `jwt` (the app's login token, as
 * `mogh_auth_client` keeps it), or the session cookie.
 */
export function MoghSupporterClient(url: string, jwt?: string) {
  const request = async <Params, Res>(
    path: "/read" | "/write",
    type: string,
    params: Params,
  ): Promise<Res> =>
    await fetchJson<Res>(`${url}${path}/${type}`, {
      method: "POST",
      body: JSON.stringify(params),
      headers: {
        "content-type": "application/json",
        ...credentialHeaders(jwt),
      },
      credentials: "include",
    });

  /** The read api: `GetSupporterKey` for every user, the rest for admins. */
  const read = async <
    T extends SupporterReadRequest["type"],
    Req extends Extract<SupporterReadRequest, { type: T }>,
  >(
    type: T,
    params: Req["params"],
  ) =>
    await request<Req["params"], SupporterReadResponses[Req["type"]]>(
      "/read",
      type,
      params,
    );

  /** The write api, for admins. */
  const write = async <
    T extends SupporterWriteRequest["type"],
    Req extends Extract<SupporterWriteRequest, { type: T }>,
  >(
    type: T,
    params: Req["params"],
  ) =>
    await request<Req["params"], SupporterWriteResponses[Req["type"]]>(
      "/write",
      type,
      params,
    );

  return { read, write };
}
