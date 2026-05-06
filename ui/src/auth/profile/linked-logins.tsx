import { useMemo } from "react";
import { Badge, Button, Text } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  AUTH_URL,
  ConfirmModal,
  DataTable,
  Section,
  useLoginOptions,
  useManageAuth,
} from "../..";
import * as MoghAuth from "mogh_auth_client";
import { CloudCog, Plus, Unlink } from "lucide-react";

function useLinkWithExternalLogin() {
  const { mutateAsync } = useManageAuth("BeginExternalLoginLink");
  return (provider: MoghAuth.Types.ExternalLoginProvider) =>
    mutateAsync({}).then(() =>
      location.replace(`${AUTH_URL}/${provider.toLowerCase()}/link`),
    );
}

export function LinkedLogins({
  refetchUser,
  passwordSet,
  oidcLinkedId,
  githubLinkedId,
  googleLinkedId,
  extraProviderFilter,
}: {
  refetchUser: () => void;
  passwordSet?: boolean;
  oidcLinkedId?: string;
  githubLinkedId?: string;
  googleLinkedId?: string;
  extraProviderFilter?: (provider: MoghAuth.Types.LoginProvider) => boolean;
}) {
  const options = useLoginOptions().data;
  const loginProviders: Array<{
    provider: MoghAuth.Types.LoginProvider;
    enabled: boolean;
    data: string | undefined;
  }> = useMemo(() => {
    return [
      {
        provider: MoghAuth.Types.LoginProvider.Local,
        enabled: !!options?.local,
        data: passwordSet ? "########" : undefined,
      },
      {
        provider: MoghAuth.Types.LoginProvider.Oidc,
        enabled: !!options?.oidc,
        data: oidcLinkedId,
      },
      {
        provider: MoghAuth.Types.LoginProvider.Github,
        enabled: !!options?.github,
        data: githubLinkedId,
      },
      {
        provider: MoghAuth.Types.LoginProvider.Google,
        enabled: !!options?.google,
        data: googleLinkedId,
      },
    ].filter(
      ({ enabled, provider }) =>
        enabled && (extraProviderFilter?.(provider) ?? true),
    );
  }, [passwordSet, oidcLinkedId, githubLinkedId, googleLinkedId, options]);
  const linkWithExternalLogin = useLinkWithExternalLogin();
  const { mutateAsync: unlink } = useManageAuth("UnlinkLogin", {
    onSuccess: () => {
      notifications.show({ message: "Unlinked login." });
      refetchUser();
    },
  });

  if (!loginProviders.length) {
    return null;
  }

  return (
    <Section
      title="Providers"
      titleFz="h3"
      icon={<CloudCog size="1.2rem" />}
      withBorder
    >
      <DataTable
        noBorder
        tableKey="login-providers-v1"
        data={loginProviders}
        columns={[
          {
            header: "Provider",
            accessorKey: "provider",
            cell: ({ row }) => <Text fw="bold">{row.original.provider}</Text>,
          },
          {
            header: "Linked",
            cell: ({
              row: {
                original: { data },
              },
            }) => (
              <Badge color={data ? "green.8" : "red"}>
                {data ? "Linked" : "Unlinked"}
              </Badge>
            ),
          },
          {
            header: "Data",
            cell: ({
              row: {
                original: { data },
              },
            }) =>
              data && (
                <Text
                  maw="20vw"
                  size="sm"
                  style={{
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    textWrap: "nowrap",
                  }}
                >
                  {data}
                </Text>
              ),
          },
          {
            header: "Link",
            cell: ({
              row: {
                original: { provider, data },
              },
            }) =>
              data ? (
                <ConfirmModal
                  icon={<Unlink size="1rem" />}
                  onConfirm={() => unlink({ provider })}
                  confirmText="Unlink"
                  title="Unlink Login"
                  confirmProps={{ variant: "filled", color: "red" }}
                >
                  Unlink
                </ConfirmModal>
              ) : provider === "Local" ? (
                <>Set password above to enable.</>
              ) : (
                <Button
                  onClick={() => linkWithExternalLogin(provider as any)}
                  leftSection={<Plus size="1rem" />}
                >
                  Link {provider}
                </Button>
              ),
          },
        ]}
      />
    </Section>
  );
}
