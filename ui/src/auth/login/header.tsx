import { Group, Stack, Text } from "@mantine/core";
import type { LoginBrandingProps } from ".";
import { useLoginOptions } from "../hooks";
import { LoginProviderButton, MAX_HEADER_LOGIN_PROVIDERS } from "./providers";

export default function LoginHeader({
  secondFactorPending,
  appName,
  iconLink,
  iconLinkAlt,
}: {
  secondFactorPending: boolean;
} & LoginBrandingProps) {
  const providers = useLoginOptions().data?.providers ?? [];
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
      {providers.length <= MAX_HEADER_LOGIN_PROVIDERS && (
        <Group gap="sm">
          {providers.map((provider) => (
            <LoginProviderButton
              key={provider.id}
              provider={provider}
              miw={110}
              maw={180}
              disabled={secondFactorPending}
            />
          ))}
        </Group>
      )}
    </Group>
  );
}
