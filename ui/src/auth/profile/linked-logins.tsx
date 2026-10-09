import { useMemo } from "react";
import { Badge, Button, Group, Text } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { ConfirmModal } from "../../components/confirm-modal";
import { DataTable } from "../../components/data-table";
import { Section } from "../../components/section";
import { authClient, useLoginOptions, useManageAuth } from "../hooks";
import { LoginProviderIcon, type LoginProviderKind } from "../login/providers";
import { CloudCog, KeyRound, Plus, Unlink } from "lucide-react";
import { markExternalFlow } from "../external-flow";

/** An external login linked to the user, as stored by the app. */
export interface LinkedLogin {
  /** The id of the external login provider. */
  provider_id: string;
  /** The id of the user at the provider. */
  external_id: string;
}

/** A row in the linked logins table. */
export interface LoginMethod {
  /** The external login provider id, or undefined for local login. */
  provider_id: string | undefined;
  /** The slug the provider's link url uses (available providers only). */
  slug?: string;
  name: string;
  /** Unknown for providers which are no longer available. */
  kind: LoginProviderKind | "Local" | undefined;
  /** Whether users can currently log in with it. */
  available: boolean;
  /** Shown when linked */
  data: string | undefined;
}

export function LinkedLogins({
  refetchUser,
  passwordSet,
  linkedLogins,
  extraProviderFilter,
}: {
  refetchUser: () => void;
  passwordSet?: boolean;
  /** The external logins linked to the user. */
  linkedLogins?: LinkedLogin[];
  extraProviderFilter?: (method: LoginMethod) => boolean;
}) {
  const options = useLoginOptions().data;
  const loginMethods: LoginMethod[] = useMemo(() => {
    const methods: LoginMethod[] = [];
    if (options?.local) {
      methods.push({
        provider_id: undefined,
        name: "Local",
        kind: "Local",
        available: true,
        data: passwordSet ? "########" : undefined,
      });
    }
    for (const provider of options?.providers ?? []) {
      methods.push({
        provider_id: provider.id,
        slug: provider.slug,
        name: provider.name,
        kind: provider.kind,
        available: true,
        data: linkedLogins?.find((login) => login.provider_id === provider.id)
          ?.external_id,
      });
    }
    // Logins linked to a provider which was since disabled or
    // deleted can't be used, but can still be unlinked.
    if (options) {
      for (const login of linkedLogins ?? []) {
        if (methods.some((m) => m.provider_id === login.provider_id)) continue;
        methods.push({
          provider_id: login.provider_id,
          name: login.provider_id,
          kind: undefined,
          available: false,
          data: login.external_id,
        });
      }
    }
    return methods.filter((method) => extraProviderFilter?.(method) ?? true);
  }, [passwordSet, linkedLogins, options]);

  // Unlinking the only login which still works would lock the user
  // out as soon as their current token expires.
  const usableLogins = loginMethods.filter(
    (method) => method.available && method.data,
  ).length;

  const { mutateAsync: beginLink } = useManageAuth("BeginExternalLoginLink");
  const onUnlinked = () => {
    notifications.show({ message: "Unlinked login." });
    refetchUser();
  };
  const { mutateAsync: unlinkLocal } = useManageAuth("UnlinkLocalLogin", {
    onSuccess: onUnlinked,
  });
  const { mutateAsync: unlinkExternal } = useManageAuth("UnlinkExternalLogin", {
    onSuccess: onUnlinked,
  });

  if (!loginMethods.length) {
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
        tableKey="login-providers-v2"
        data={loginMethods}
        columns={[
          {
            header: "Provider",
            accessorKey: "name",
            cell: ({ row: { original: method } }) => (
              <Group gap="xs" wrap="nowrap">
                {method.kind === "Local" ? (
                  <KeyRound size="1rem" />
                ) : (
                  method.kind && <LoginProviderIcon kind={method.kind} />
                )}
                <Text fw="bold">{method.name}</Text>
              </Group>
            ),
          },
          {
            header: "Linked",
            cell: ({ row: { original: method } }) =>
              !method.available ? (
                <Badge color="gray">Unavailable</Badge>
              ) : (
                <Badge color={method.data ? "green.8" : "red"}>
                  {method.data ? "Linked" : "Unlinked"}
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
            cell: ({ row: { original: method } }) => {
              const providerId = method.provider_id;
              if (method.data) {
                if (method.available && usableLogins <= 1) {
                  return (
                    <Text size="sm" c="dimmed">
                      Your only login. Add another one to unlink it.
                    </Text>
                  );
                }
                return (
                  <ConfirmModal
                    icon={<Unlink size="1rem" />}
                    onConfirm={() =>
                      providerId === undefined
                        ? unlinkLocal({})
                        : unlinkExternal({ provider_id: providerId })
                    }
                    confirmText="Unlink"
                    title="Unlink Login"
                    confirmProps={{ variant: "filled", color: "red" }}
                  >
                    Unlink
                  </ConfirmModal>
                );
              }
              if (providerId === undefined) {
                return <>Set password above to enable.</>;
              }
              // The url names the provider by its slug. The link begun on
              // the session is bound to it: the server refuses to start
              // it at another provider's `/link`.
              const slug = method.slug ?? providerId;
              return (
                <Button
                  // Through the mutation for its error notification
                  onClick={() =>
                    beginLink({ slug })
                      .then(() => {
                        // The reason a failed link comes back
                        // with is shown (see `useAuthState`).
                        markExternalFlow();
                        location.replace(authClient().externalLinkUrl(slug));
                      })
                      // Notified by the mutation.
                      .catch(() => {})
                  }
                  leftSection={<Plus size="1rem" />}
                  maw={220}
                  title={`Link ${method.name}`}
                >
                  Link {method.name}
                </Button>
              );
            },
          },
        ]}
      />
    </Section>
  );
}
