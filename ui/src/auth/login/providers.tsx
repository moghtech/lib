import { Button, ButtonProps, useComputedColorScheme } from "@mantine/core";
import { KeyRound } from "lucide-react";
import * as MoghAuth from "mogh_auth_client";
import { externalLogin } from "../hooks";

/**
 * The login header has room for this many provider buttons.
 * With more configured, they are listed in the login form instead.
 */
export const MAX_HEADER_LOGIN_PROVIDERS = 3;

/**
 * The kind of an external login provider, accepting both
 * the `ExternalLoginKind` enum and its string values.
 */
export type LoginProviderKind = `${MoghAuth.Types.ExternalLoginKind}`;

/**
 * Icon for the kind of external login provider.
 * Github and Google expect `/icons/github.svg` and `/icons/google.svg`
 * to be served by the host app.
 */
export function LoginProviderIcon({
  kind,
  size = "1rem",
}: {
  kind: LoginProviderKind;
  size?: string | number;
}) {
  const theme = useComputedColorScheme();
  if (kind === "Oidc") {
    return <KeyRound size={size} />;
  }
  return (
    <img
      src={`/icons/${kind.toLowerCase()}.svg`}
      alt={kind}
      style={{
        width: size,
        height: size,
        filter: theme === "dark" ? "invert(1)" : undefined,
      }}
    />
  );
}

export function LoginProviderButton({
  provider,
  ...props
}: {
  provider: MoghAuth.Types.LoginOptionsProvider;
} & ButtonProps) {
  return (
    <Button
      onClick={() => externalLogin(provider.slug)}
      leftSection={<LoginProviderIcon kind={provider.kind} />}
      title={provider.name}
      {...props}
    >
      {provider.name}
    </Button>
  );
}
