import {
  Button,
  Group,
  Stack,
  Text,
  useComputedColorScheme,
} from "@mantine/core";
import { KeyRound } from "lucide-react";
import * as MoghAuth from "mogh_auth_client";
import { LoginBrandingProps } from ".";
import { authClient, useLoginOptions } from "../..";

export default function LoginHeader({
  secondFactorPending,
  appName,
  iconLink,
  iconLinkAlt,
}: {
  secondFactorPending: boolean;
} & LoginBrandingProps) {
  const options = useLoginOptions().data;
  const theme = useComputedColorScheme();
  return (
    <Group justify="space-between">
      <Group gap="sm">
        <img src={iconLink} width={42} height={42} alt={iconLinkAlt} />
        <Stack gap="0">
          <Text fz="h2" fw="450" lts="0.1rem">
            {appName}
          </Text>
          <Text size="md" opacity={0.6} mt={-8}>
            Log In
          </Text>
        </Stack>
      </Group>
      <Group gap="sm">
        {(
          [
            [options?.oidc, "Oidc"],
            [options?.github, "Github"],
            [options?.google, "Google"],
          ] as Array<
            [boolean | undefined, MoghAuth.Types.ExternalLoginProvider]
          >
        ).map(
          ([enabled, provider]) =>
            enabled && (
              <Button
                key={provider}
                onClick={() => authClient().externalLogin(provider)}
                leftSection={
                  provider === "Oidc" ? (
                    <KeyRound size="1rem" />
                  ) : (
                    <img
                      src={`/icons/${provider.toLowerCase()}.svg`}
                      alt={provider}
                      style={{
                        width: "1rem",
                        height: "1rem",
                        filter: theme === "dark" ? "invert(1)" : undefined,
                      }}
                    />
                  )
                }
                w={110}
                disabled={secondFactorPending}
              >
                {provider}
              </Button>
            ),
        )}
      </Group>
    </Group>
  );
}
