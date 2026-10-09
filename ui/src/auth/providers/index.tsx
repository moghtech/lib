import { useState } from "react";
import {
  Badge,
  Group,
  SegmentedControl,
  Stack,
  Text,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useQueryClient } from "@tanstack/react-query";
import { KeyRound, Trash } from "lucide-react";
import { useNavigate } from "react-router-dom";
import * as MoghAuth from "mogh_auth_client";
import { ConfirmModal } from "../../components/confirm-modal";
import { CopyText } from "../../components/copy-text";
import { CreateModal } from "../../components/create-modal";
import { DataTable } from "../../components/data-table";
import { ItemLink } from "../../components/item-link";
import { SearchInput } from "../../components/search-input";
import { Section, type SectionProps } from "../../components/section";
import { filterBySplit } from "../../utils";
import { useExternalLoginProviders, useManageAuth } from "../hooks";
import { LoginProviderIcon, LoginProviderKind } from "../login/providers";

export * from "./page";

type ListItem = MoghAuth.Types.ExternalLoginProviderListItem;

const KINDS: { value: LoginProviderKind; label: string }[] = [
  { value: "Oidc", label: "OIDC" },
  { value: "Github", label: "Github" },
  { value: "Google", label: "Google" },
];

/** New providers start disabled, they can't work before they are configured. */
function newProviderConfig(
  kind: LoginProviderKind,
): MoghAuth.Types.ExternalLoginProviderConfig {
  return {
    kind,
    params: { enabled: false },
  } as MoghAuth.Types.ExternalLoginProviderConfig;
}

/**
 * Manage the external login providers (OIDC, Github, Google)
 * users can use to log in. For use in app settings pages.
 *
 * Each provider is viewed and edited on its page, the app's route of
 * `LoginProviderPage` (`link`): the names link there, and a new
 * provider (its kind and name) continues there for its configuration.
 *
 * The API behind it is limited to admin users, see `AuthUserImpl::is_admin`.
 * Providers from the app configuration are listed read only.
 */
export function LoginProvidersTable({
  link,
  ...sectionProps
}: {
  /** The route of a provider's page (`LoginProviderPage`), by its id. */
  link: (id: string) => string;
} & SectionProps) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { data: providers, isPending, error } = useExternalLoginProviders();

  // The login page and linked logins show the enabled providers
  const invalidate = () =>
    Promise.all([
      queryClient.invalidateQueries({
        queryKey: ["ListExternalLoginProviders"],
      }),
      queryClient.invalidateQueries({ queryKey: ["GetLoginOptions"] }),
    ]);

  const [newKind, setNewKind] = useState<LoginProviderKind>("Oidc");
  const [newName, setNewName] = useState("");
  const { mutateAsync: create, isPending: createPending } = useManageAuth(
    "CreateExternalLoginProvider",
  );
  const { mutateAsync: deleteProvider, isPending: deletePending } =
    useManageAuth("DeleteExternalLoginProvider", {
      onSuccess: () => {
        notifications.show({ message: "Deleted login provider." });
        invalidate();
      },
    });

  const [search, setSearch] = useState("");
  const filtered = filterBySplit(
    providers,
    search,
    (item) => item.provider.name,
  );

  return (
    <Section
      title="Login Providers"
      titleFz="h3"
      icon={<KeyRound size="1.2rem" />}
      description="External providers users can use to log in."
      isPending={isPending}
      error={
        error
          ? (((error as any)?.result?.error as string | undefined) ??
            "Failed to load login providers")
          : false
      }
      {...sectionProps}
    >
      <Group>
        <CreateModal
          entityType="Login Provider"
          configureLabel="the kind and a display name"
          modalSize="xl"
          loading={createPending}
          disabled={!newName.trim().length}
          onOpenChange={(opened) => opened && setNewName("")}
          onConfirm={() =>
            create({
              name: newName.trim(),
              registration_disabled: false,
              config: newProviderConfig(newKind),
            })
              .then(async (item) => {
                await invalidate();
                // Continue to the full configuration, which
                // shows the redirect URI of the new provider.
                navigate(link(item.provider.id), {
                  state: { justCreated: true },
                });
                return true;
              })
              .catch(() => false)
          }
          configSection={() => (
            <Stack>
              <SegmentedControl
                value={newKind}
                onChange={(kind) => setNewKind(kind as LoginProviderKind)}
                data={KINDS}
                fullWidth
              />
              <TextInput
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                label="Name"
                description="Shown on the login button"
                placeholder="eg. Company SSO"
                data-autofocus
              />
            </Stack>
          )}
        />
        <SearchInput value={search} onSearch={setSearch} />
      </Group>
      <DataTable
        noBorder
        tableKey="manage-login-providers-v1"
        data={filtered}
        noResults={
          <Text c="dimmed">No external login providers configured.</Text>
        }
        onRowClick={(item) => navigate(link(item.provider.id))}
        columns={[
          {
            header: "Name",
            accessorFn: (item: ListItem) => item.provider.name,
            cell: ({ row: { original: item } }) => (
              <ItemLink
                name={item.provider.name}
                icon={<LoginProviderIcon kind={item.provider.config.kind} />}
                to={link(item.provider.id)}
                gap="0.5rem"
              />
            ),
          },
          {
            header: "Kind",
            accessorFn: (item: ListItem) => item.provider.config.kind,
            cell: ({ row: { original: item } }) =>
              KINDS.find((kind) => kind.value === item.provider.config.kind)
                ?.label,
          },
          {
            header: "Status",
            accessorFn: (item: ListItem) =>
              item.provider.config.params.enabled ? "Enabled" : "Disabled",
            cell: ({ row: { original: item } }) => {
              const enabled = item.provider.config.params.enabled;
              return (
                <Group gap="xs" wrap="nowrap">
                  <Badge color={enabled ? "green.8" : "red"}>
                    {enabled ? "Enabled" : "Disabled"}
                  </Badge>
                  {item.provider.registration_disabled && (
                    <Badge color="gray" title="New user registration disabled">
                      No sign up
                    </Badge>
                  )}
                  {item.provider.token_exchange?.enabled && (
                    <Badge color="yellow" title="Token exchange enabled">
                      Token exchange
                    </Badge>
                  )}
                </Group>
              );
            },
          },
          {
            header: "Redirect URI",
            cell: ({ row: { original: item } }) => (
              <CopyText
                content={item.redirect_uri}
                label="redirect URI"
                groupProps={{ onClick: (e) => e.stopPropagation() }}
              />
            ),
          },
          {
            header: "Source",
            accessorFn: (item: ListItem) =>
              item.read_only ? "Config" : "Managed",
            cell: ({ row: { original: item } }) =>
              item.read_only ? (
                <Badge
                  color="gray"
                  title="From the app configuration, read only"
                >
                  Config
                </Badge>
              ) : (
                <Badge color="blue">Managed</Badge>
              ),
          },
          {
            header: "Actions",
            cell: ({ row: { original: item } }) => (
              <Group gap="xs" wrap="nowrap">
                {!item.read_only && (
                  <ConfirmModal
                    icon={<Trash size="1rem" />}
                    confirmText={item.provider.name}
                    title="Delete Login Provider"
                    loading={deletePending}
                    onConfirm={() => deleteProvider({ id: item.provider.id })}
                    targetProps={{ w: "fit-content" }}
                    confirmProps={{ variant: "filled", color: "red" }}
                    topAdditonal={
                      <Text>
                        Users can no longer log in with{" "}
                        <b>{item.provider.name}</b>, and their links to it are
                        removed. Users without another login method lose access.
                        To pause it instead, disable the provider.
                      </Text>
                    }
                  >
                    Delete
                  </ConfirmModal>
                )}
              </Group>
            ),
          },
        ]}
      />
    </Section>
  );
}
