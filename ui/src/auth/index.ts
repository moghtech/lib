import { notifications } from "@mantine/notifications";
import {
  useMutation,
  UseMutationOptions,
  useQuery,
} from "@tanstack/react-query";
import * as MoghAuth from "mogh_auth_client";
import { sanitizeQueryInner } from "./utils";

export * from "./login";
export * from "./profile";
export * from "./utils";

export let AUTH_URL: string;

/**
 * Set the global auth url.
 * Make sure to call this before first render.
 * @param url The global url
 */
export function setAuthUrl(url: string) {
  AUTH_URL = url;
}

export function authClient() {
  return MoghAuth.MoghAuthClient(AUTH_URL, MoghAuth.LOGIN_TOKENS.jwt());
}

export function useLoginOptions() {
  return useQuery({
    queryKey: ["GetLoginOptions"],
    queryFn: () => authClient().login("GetLoginOptions", {}),
  });
}

export function useLogin<
  T extends MoghAuth.Types.LoginRequest["type"],
  R extends Extract<MoghAuth.Types.LoginRequest, { type: T }>,
  P extends R["params"],
  C extends Omit<
    UseMutationOptions<MoghAuth.LoginResponses[T], unknown, P, unknown>,
    "mutationKey" | "mutationFn"
  >,
>(type: T, config?: C) {
  return useMutation({
    mutationKey: [type],
    mutationFn: (params: P) => authClient().login<T, R>(type, params),
    onError: (e: { result: { error?: string; trace?: string[] } }, ...args) => {
      console.log("Login error:", e);
      const msg = e.result.error ?? "Unknown error. See console.";
      const detail = e.result?.trace
        ?.map((msg) => msg[0].toUpperCase() + msg.slice(1))
        .join(" | ");
      let msg_log = msg ? msg[0].toUpperCase() + msg.slice(1) + " | " : "";
      if (detail) {
        msg_log += detail + " | ";
      }
      notifications.show({
        title: `Login request ${type} failed`,
        message: `${msg_log}See console for details`,
        color: "red",
      });
      config?.onError && config.onError(e, ...args);
    },
    ...config,
  });
}

export function useManageAuth<
  T extends MoghAuth.Types.ManageRequest["type"],
  R extends Extract<MoghAuth.Types.ManageRequest, { type: T }>,
  P extends R["params"],
  C extends Omit<
    UseMutationOptions<MoghAuth.ManageResponses[T], unknown, P, unknown>,
    "mutationKey" | "mutationFn"
  >,
>(type: T, config?: C) {
  return useMutation({
    mutationKey: [type],
    mutationFn: (params: P) => authClient().manage<T, R>(type, params),
    onError: (e: { result: { error?: string; trace?: string[] } }, ...args) => {
      console.log("Manage auth error:", e);
      const msg = e.result.error ?? "Unknown error. See console.";
      const detail = e.result?.trace
        ?.map((msg) => msg[0].toUpperCase() + msg.slice(1))
        .join(" | ");
      let msg_log = msg ? msg[0].toUpperCase() + msg.slice(1) + " | " : "";
      if (detail) {
        msg_log += detail + " | ";
      }
      notifications.show({
        title: `Manage auth request ${type} failed`,
        message: `${msg_log}See console for details`,
        color: "red",
      });
      config?.onError && config.onError(e, ...args);
    },
    ...config,
  });
}

let jwt_redeem_sent = false;
let passkey_sent = false;

/// returns whether to show login / loading screen depending on state of exchange token loop
export function useAuthState() {
  const onSuccess = ({ jwt }: MoghAuth.Types.JwtResponse) => {
    MoghAuth.LOGIN_TOKENS.add_and_change(jwt);
    sanitizeQueryInner(search);
  };
  const { mutate: redeemJwt } = useLogin("ExchangeForJwt", {
    onSuccess,
  });
  const { mutate: completePasskeyLogin } = useLogin("CompletePasskeyLogin", {
    onSuccess,
  });
  const search = new URLSearchParams(location.search);

  const _passkey = search.get("passkey");
  const passkey = _passkey
    ? JSON.parse(MoghAuth.Passkey.base64UrlDecode(_passkey))
    : null;

  // guard against multiple reqs sent
  // maybe isPending would do this but not sure about with render loop, this for sure will.
  if (passkey && !passkey_sent) {
    navigator.credentials
      .get(MoghAuth.Passkey.prepareRequestChallengeResponse(passkey))
      .then((credential) => completePasskeyLogin({ credential }))
      .catch((e) => {
        console.error(e);
        notifications.show({
          title: "Failed to select passkey",
          message: "See console for details",
          color: "red",
        });
      });
    passkey_sent = true;
  }

  const jwt_redeem_ready = search.get("redeem_ready") === "true";

  // guard against multiple reqs sent
  // maybe isPending would do this but not sure about with render loop, this for sure will.
  if (jwt_redeem_ready && !jwt_redeem_sent) {
    redeemJwt({});
    jwt_redeem_sent = true;
  }

  return {
    jwt_redeem_ready,
    passkey_pending: !!passkey,
    totp: search.get("totp") === "true",
  };
}
