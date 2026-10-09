import {
  Button,
  Center,
  Divider,
  Fieldset,
  Group,
  Loader,
  PasswordInput,
  SimpleGrid,
  Text,
  TextInput,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { notifications } from "@mantine/notifications";
import * as MoghAuth from "mogh_auth_client";
import { AlertTriangle, ChevronLeft, KeyRound } from "lucide-react";
import { useEffect, useState } from "react";
import { useInRouterContext } from "react-router-dom";
import LoginHeader from "./header";
import { LoginProviderButton, MAX_HEADER_LOGIN_PROVIDERS } from "./providers";
import {
  externalLoginState,
  flowReturnParam,
  isLoginPath,
} from "../external-flow";
import { type PasskeyRequest, passkeyRequestFromParam } from "../passkey-login";

export * from "./providers";
import { BackButton } from "../../components/back-button";
import { externalLogin, useLogin, useLoginOptions, useUserId } from "../hooks";
import { backtoPath, sanitizeQuery } from "../utils";

export interface LoginBrandingProps {
  appName: string;
  iconLink: string;
  iconLinkAlt: string;
}

export function LoginPage({
  passkeyIsPending: _passkeyIsPending,
  totpIsPending: _totpIsPending,
  alreadyLoggedIn: _alreadyLoggedIn,
  onLogin,
  exampleConfigLink,
  ...branding
}: {
  passkeyIsPending?: boolean;
  totpIsPending?: boolean;
  /**
   * Whether another user is already signed in, which puts a back button
   * on the form. Pass it from the host app's own session query. Left
   * out, the login page has to query the api itself. A token the server
   * rejects is only sent once, but that request counts against its
   * auth rate limit.
   */
  alreadyLoggedIn?: boolean;
  onLogin?: () => void;
  exampleConfigLink: string;
} & LoginBrandingProps) {
  const options = useLoginOptions().data;
  const [passkeyIsPending, setPasskeyPending] = useState(
    _passkeyIsPending ?? false,
  );
  const [totpIsPending, setTotpPending] = useState(_totpIsPending ?? false);
  const secondFactorPending = passkeyIsPending || totpIsPending;

  const userId = useUserId({ enabled: _alreadyLoggedIn === undefined });
  const alreadyLoggedIn = _alreadyLoggedIn ?? !!userId.data?.id;

  // Auto-redirect to the configured provider if disableAutoLogin is
  // not set. Not after an external login failed on this page load
  // (`login_error`, see `useAuthState`): the provider would be asked
  // again and again, and the user would never see why.
  useEffect(() => {
    if (options?.auto_redirect && !secondFactorPending) {
      const params = new URLSearchParams(location.search);
      if (
        !params.has("disableAutoLogin") &&
        !params.has("login_error") &&
        !externalLoginState.failed
      ) {
        externalLogin(options.auto_redirect);
      }
    }
  }, [options?.auto_redirect, secondFactorPending]);

  // On the login route, go on to `backto` after logging in: the app's
  // router doesn't leave it by itself (eg. when signing in another
  // user). Elsewhere (eg. the second factor of an external login which
  // returned to a page of the app) stay on the page, also when its path
  // only starts with `/login` (eg. `/login-providers/:id`).
  const maybeNavigate = isLoginPath(location.pathname)
    ? () => location.replace(backtoPath())
    : undefined;

  const onSuccess = ({ jwt }: MoghAuth.Types.JwtResponse) => {
    MoghAuth.LOGIN_TOKENS.add_and_change(jwt);
    onLogin?.();
    maybeNavigate?.();
  };

  const secondFactorOnSuccess = (res: MoghAuth.Types.JwtResponse) => {
    sanitizeQuery();
    onSuccess(res);
  };

  const { mutate: signup, isPending: signupPending } = useLogin(
    "SignUpLocalUser",
    {
      onSuccess,
    },
  );

  const { mutate: completePasskeyLogin } = useLogin("CompletePasskeyLogin", {
    onSuccess: secondFactorOnSuccess,
  });

  // The passkey request of the pending login, kept for "Try Again" when
  // the prompt was dismissed, timed out or failed: rather than starting
  // the login over (the password, or the provider's round trip). After
  // an external login it is in the url, which `useAuthState` prompts for
  // first.
  const [passkeyRequest, setPasskeyRequest] = useState<
    PasskeyRequest | undefined
  >(() => {
    const encoded = _passkeyIsPending
      ? flowReturnParam(new URLSearchParams(location.search), "passkey")
      : null;
    try {
      return encoded ? passkeyRequestFromParam(encoded) : undefined;
    } catch {
      // `useAuthState` says so.
      return undefined;
    }
  });
  const [passkeyPrompt, setPasskeyPrompt] = useState(false);
  const providePasskey = (request: PasskeyRequest) => {
    setPasskeyPrompt(true);
    navigator.credentials
      .get(request)
      .then((credential) => completePasskeyLogin({ credential }))
      .catch((e) => {
        console.error(e);
        notifications.show({
          title: "Failed to select passkey",
          message: "See console for details",
          color: "red",
        });
      })
      .finally(() => setPasskeyPrompt(false));
  };

  // Entering a recovery code in place of the authenticator code.
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);

  /** Back to the first factor, eg. to log in as somebody else. */
  const cancelSecondFactor = () => {
    setPasskeyPending(false);
    setPasskeyRequest(undefined);
    setTotpPending(false);
    setUseRecoveryCode(false);
    // After an external login the second factor is asked for by the url.
    const search = new URLSearchParams(location.search);
    if (search.has("totp") || search.has("passkey")) {
      sanitizeQuery();
    }
  };

  // A mistyped code can be tried again. Once the server has ended the
  // login (too many invalid codes, the login expired, or the session
  // expired) more codes can't succeed, so go back to the first factor.
  const secondFactorOnError = (e: unknown) => {
    const error =
      (e as { result?: { error?: string } } | undefined)?.result?.error ?? "";
    if (
      error.includes("Too many invalid codes") ||
      error.includes("Login has expired") ||
      error.includes("has not been initiated")
    ) {
      cancelSecondFactor();
    }
  };

  const { mutate: completeTotpLogin, isPending: totpPending } = useLogin(
    "CompleteTotpLogin",
    {
      onSuccess: secondFactorOnSuccess,
      onError: secondFactorOnError,
    },
  );

  const { mutate: completeTotpRecoveryLogin, isPending: recoveryPending } =
    useLogin("CompleteTotpRecoveryLogin", {
      onSuccess: secondFactorOnSuccess,
      onError: secondFactorOnError,
    });

  const { mutate: login, isPending: loginPending } = useLogin(
    "LoginLocalUser",
    {
      onSuccess: ({ type, data }) => {
        switch (type) {
          case "Jwt":
            return onSuccess(data);
          case "Passkey": {
            const request =
              MoghAuth.Passkey.prepareRequestChallengeResponse(data);
            setPasskeyRequest(request);
            setPasskeyPending(true);
            return providePasskey(request);
          }
          case "Totp":
            return setTotpPending(true);
        }
      },
    },
  );

  const providers = options?.providers ?? [];

  // The header only has room for a few providers
  const providersInForm =
    providers.length > MAX_HEADER_LOGIN_PROVIDERS && !secondFactorPending;

  const noAuthConfigured =
    options !== undefined && !options.local && providers.length === 0;

  const showSignUp = options !== undefined && !options.registration_disabled;

  const localForm = useForm({
    mode: "uncontrolled",
    initialValues: {
      username: "",
      password: "",
    },
    validate: {
      username: (username) =>
        username.length ? null : "Username cannot be empty",
      password: (password) =>
        password.length ? null : "Password cannot be empty",
    },
  });

  const totpForm = useForm({
    mode: "uncontrolled",
    initialValues: {
      code: "",
    },
    validate: {
      code: (code) => (code.length === 6 ? null : "Code should be 6 digits"),
    },
  });

  const recoveryForm = useForm({
    mode: "uncontrolled",
    initialValues: {
      code: "",
    },
    validate: {
      code: (code) =>
        code.trim().length ? null : "Recovery code cannot be empty",
    },
  });

  return (
    <Center h="80vh">
      <Fieldset
        legend={
          <LoginHeader
            secondFactorPending={secondFactorPending}
            {...branding}
          />
        }
        component="form"
        onSubmit={
          totpIsPending
            ? useRecoveryCode
              ? recoveryForm.onSubmit(({ code }) =>
                  completeTotpRecoveryLogin({ code: code.trim() }),
                )
              : totpForm.onSubmit((form) => completeTotpLogin(form))
            : (localForm.onSubmit((form) => login(form)) as any)
        }
        style={{ display: "flex", flexDirection: "column", gap: "1rem" }}
        miw={{ base: "95vw", xs: "530px" }}
        maw="95vw"
      >
        {options?.local && !secondFactorPending && (
          <>
            <TextInput
              {...localForm.getInputProps("username")}
              autoFocus
              label="Username"
              placeholder="Enter username"
              autoComplete="username"
              autoCapitalize="off"
              autoCorrect="off"
              key={localForm.key("username")}
            />
            <PasswordInput
              {...localForm.getInputProps("password")}
              label="Password"
              placeholder="Enter password"
              autoComplete="current-password"
              autoCapitalize="off"
              autoCorrect="off"
              key={localForm.key("password")}
            />
            <Group mt="sm" justify="space-between">
              {alreadyLoggedIn && <LoginBackButton />}
              <Group justify="end">
                {showSignUp && (
                  <Button
                    variant="outline"
                    w={110}
                    onClick={localForm.onSubmit((form) => signup(form)) as any}
                    loading={signupPending}
                  >
                    Sign Up
                  </Button>
                )}
                <Button w={110} type="submit" loading={loginPending}>
                  Log In
                </Button>
              </Group>
            </Group>
          </>
        )}

        {providersInForm && (
          <>
            {options?.local && (
              <Divider label="Or continue with" labelPosition="center" />
            )}
            <SimpleGrid cols={{ base: 1, xs: 2 }} spacing="sm">
              {providers.map((provider) => (
                <LoginProviderButton
                  key={provider.id}
                  provider={provider}
                  variant="default"
                  fullWidth
                />
              ))}
            </SimpleGrid>
          </>
        )}

        {/* During the second factor, Cancel is the way back. */}
        {alreadyLoggedIn && !options?.local && !secondFactorPending && (
          <Group>
            <LoginBackButton />
          </Group>
        )}

        {passkeyIsPending && (
          <>
            <Group justify="center" my="lg">
              <KeyRound size="1.5rem" />
              <Text size="lg">Provide your passkey to finish login...</Text>
              <Loader />
            </Group>
            <Group>
              <Button variant="default" onClick={cancelSecondFactor}>
                Cancel
              </Button>
              {passkeyRequest && (
                <Button
                  leftSection={<KeyRound size="1rem" />}
                  loading={passkeyPrompt}
                  onClick={() => providePasskey(passkeyRequest)}
                >
                  Try Again
                </Button>
              )}
            </Group>
          </>
        )}

        {totpIsPending && (
          <>
            {useRecoveryCode ? (
              <TextInput
                {...recoveryForm.getInputProps("code")}
                key={recoveryForm.key("code")}
                label={
                  <Group gap="sm">
                    <KeyRound size="1rem" />
                    Recovery Code
                  </Group>
                }
                description="One of the codes saved when 2FA was set up. Each works once."
                autoComplete="off"
                autoCapitalize="none"
                autoCorrect="off"
                autoFocus
              />
            ) : (
              <TextInput
                {...totpForm.getInputProps("code")}
                key={totpForm.key("code")}
                label={
                  <Group gap="sm">
                    <KeyRound size="1rem" />
                    2FA Code
                  </Group>
                }
                autoComplete="one-time-code"
                inputMode="numeric"
                autoCapitalize="none"
                autoCorrect="off"
                autoFocus
              />
            )}
            <Group justify="space-between">
              <Group gap="xs">
                <Button variant="default" onClick={cancelSecondFactor}>
                  Cancel
                </Button>
                <Button
                  variant="subtle"
                  onClick={() => setUseRecoveryCode((use) => !use)}
                >
                  {useRecoveryCode
                    ? "Use authenticator code"
                    : "Use a recovery code"}
                </Button>
              </Group>
              <Button
                w={110}
                variant="filled"
                type="submit"
                loading={totpPending || recoveryPending}
              >
                Log In
              </Button>
            </Group>
          </>
        )}

        {noAuthConfigured && (
          <Group my="lg">
            <AlertTriangle size="2rem" />
            <Text>
              No login methods have been configured. <br />
              See the{" "}
              <a
                href={exampleConfigLink}
                target="_blank"
                rel="noreferrer"
                className="hover-underline"
              >
                <b>example config</b>
              </a>{" "}
              for information on configuring auth.
            </Text>
          </Group>
        )}
      </Fieldset>
    </Center>
  );
}

/**
 * Back to `backto` (see `backtoPath`), for a user who is already
 * signed in. The login page is also rendered outside the host app's
 * router (the second factor after an external login), where a router
 * link can't be rendered.
 */
function LoginBackButton() {
  const inRouter = useInRouterContext();
  const to = backtoPath();
  if (inRouter) {
    return <BackButton to={to} />;
  }
  return (
    <Button component="a" href={to} leftSection={<ChevronLeft size="1rem" />}>
      Back
    </Button>
  );
}
