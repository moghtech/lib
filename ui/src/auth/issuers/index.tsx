import { useState } from "react";
import { Badge, Group, Stack, Text, TextInput } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useQueryClient } from "@tanstack/react-query";
import { Fingerprint, ServerCog, Trash } from "lucide-react";
import { useNavigate } from "react-router-dom";
import * as MoghAuth from "mogh_auth_client";
import { hexColorByIntention } from "../../color";
import { ConfirmModal } from "../../components/confirm-modal";
import { CreateModal } from "../../components/create-modal";
import { DataTable } from "../../components/data-table";
import { ItemLink } from "../../components/item-link";
import { SearchInput } from "../../components/search-input";
import { Section, type SectionProps } from "../../components/section";
import { filterBySplit } from "../../utils";
import { useManageAuth, useTrustedIssuers } from "../hooks";

export * from "./page";

type ListItem = MoghAuth.Types.TrustedIssuerListItem;

/**
 * Manage the token issuers trusted for workload identity: CI jobs,
 * Kubernetes service accounts and other machines exchange the token
 * their platform issues them for an app token, without an api key.
 * For use in app settings pages.
 *
 * Each issuer is viewed and edited on its page, the app's route of
 * `TrustedIssuerPage` (`link`): the names link there, and a new
 * issuer (name, issuer url and audience, created disabled) continues
 * there for its rules.
 *
 * The API behind it is limited to admin users, see `AuthUserImpl::is_admin`.
 * Issuers from the app configuration are listed read only.
 */
export function TrustedIssuersTable({
  link,
  ...sectionProps
}: {
  /** The route of an issuer's page (`TrustedIssuerPage`), by its id. */
  link: (id: string) => string;
} & SectionProps) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { data: issuers, isPending, error } = useTrustedIssuers();

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["ListTrustedIssuers"] });

  // Created with the minimum, the page continues with its rules.
  const [newIssuer, setNewIssuer] = useState({
    name: "",
    issuer: "",
    audience: location.origin,
  });
  const { mutateAsync: create, isPending: createPending } = useManageAuth(
    "CreateTrustedIssuer",
  );

  const { mutateAsync: deleteIssuer, isPending: deletePending } = useManageAuth(
    "DeleteTrustedIssuer",
    {
      onSuccess: () => {
        notifications.show({ message: "Deleted trusted issuer." });
        invalidate();
      },
    },
  );

  const [search, setSearch] = useState("");
  const filtered = filterBySplit(issuers, search, (item) => item.issuer.name);

  return (
    <Section
      title="Trusted Issuers"
      titleFz="h3"
      icon={<ServerCog size="1.2rem" />}
      description="Trusted issuers allow CI workloads to acquire short lived auth tokens on demand."
      isPending={isPending}
      error={
        error
          ? (((error as any)?.result?.error as string | undefined) ??
            "Failed to load trusted issuers")
          : false
      }
      {...sectionProps}
    >
      <Group>
        <CreateModal
          entityType="Trusted Issuer"
          configureLabel="the name, issuer and audience"
          modalSize="xl"
          loading={createPending}
          disabled={!newIssuer.name.trim() || !newIssuer.issuer.trim()}
          onOpenChange={(opened) => {
            if (opened) {
              setNewIssuer({
                name: "",
                issuer: "",
                audience: location.origin,
              });
            }
          }}
          onConfirm={() =>
            create({
              issuer: {
                id: "",
                name: newIssuer.name.trim(),
                // Disabled until it has rules
                enabled: false,
                issuer: newIssuer.issuer.trim(),
                keys: { source: "Discovery", params: {} },
                audiences: newIssuer.audience.trim()
                  ? [newIssuer.audience.trim()]
                  : [],
                max_token_age_secs: 300,
                rules: [],
              },
            })
              .then(async (item) => {
                await invalidate();
                navigate(link(item.issuer.id));
                return true;
              })
              .catch(() => false)
          }
          configSection={() => (
            <Stack>
              <TextInput
                value={newIssuer.name}
                onChange={(e) =>
                  setNewIssuer({ ...newIssuer, name: e.target.value })
                }
                label="Name"
                placeholder="eg. Github Actions"
                data-autofocus
              />
              <TextInput
                value={newIssuer.issuer}
                onChange={(e) =>
                  setNewIssuer({ ...newIssuer, issuer: e.target.value })
                }
                label="Issuer"
                description="The issuer (iss) of the tokens"
                placeholder="https://token.actions.githubusercontent.com"
              />
              <TextInput
                value={newIssuer.audience}
                onChange={(e) =>
                  setNewIssuer({ ...newIssuer, audience: e.target.value })
                }
                label="Audience"
                description="The audience (aud) the workload requests its token for. Use one specific to this app. More can be added on the issuer's page."
                placeholder="https://example.com"
              />
            </Stack>
          )}
        />
        <SearchInput value={search} onSearch={setSearch} />
      </Group>
      <DataTable
        noBorder
        tableKey="manage-trusted-issuers-v1"
        data={filtered}
        noResults={<Text c="dimmed">No trusted issuers configured.</Text>}
        onRowClick={(item) => navigate(link(item.issuer.id))}
        columns={[
          {
            header: "Name",
            accessorFn: (item: ListItem) => item.issuer.name,
            cell: ({ row: { original: item } }) => (
              <ItemLink
                name={item.issuer.name}
                icon={
                  <Fingerprint
                    size="1rem"
                    color={hexColorByIntention(
                      item.issuer.enabled ? "Good" : "Critical",
                    )}
                  />
                }
                to={link(item.issuer.id)}
                gap="0.5rem"
              />
            ),
          },
          {
            header: "Issuer",
            accessorFn: (item: ListItem) => item.issuer.issuer,
            cell: ({ row: { original: item } }) => (
              <Text
                size="sm"
                maw="30vw"
                title={item.issuer.issuer}
                style={{
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  textWrap: "nowrap",
                }}
              >
                {item.issuer.issuer}
              </Text>
            ),
          },
          {
            header: "Status",
            accessorFn: (item: ListItem) =>
              item.issuer.enabled ? "Enabled" : "Disabled",
            cell: ({ row: { original: item } }) => (
              <Badge color={item.issuer.enabled ? "green.8" : "red"}>
                {item.issuer.enabled ? "Enabled" : "Disabled"}
              </Badge>
            ),
          },
          {
            header: "Rules",
            accessorFn: (item: ListItem) =>
              String(item.issuer.rules?.length ?? 0),
            cell: ({ row: { original: item } }) => {
              const rules = item.issuer.rules ?? [];
              const enabled = rules.filter((rule) => rule.enabled).length;
              return (
                <Group gap="xs" wrap="nowrap">
                  <Text size="sm">
                    {enabled === rules.length
                      ? rules.length
                      : `${enabled} of ${rules.length} enabled`}
                  </Text>
                  {rules.some((rule) => rule.enabled && rule.admin) && (
                    <Badge color="yellow" title="A rule grants admin">
                      Admin
                    </Badge>
                  )}
                </Group>
              );
            },
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
                    confirmText={item.issuer.name}
                    title="Delete Trusted Issuer"
                    loading={deletePending}
                    onConfirm={() => deleteIssuer({ id: item.issuer.id })}
                    targetProps={{ w: "fit-content" }}
                    confirmProps={{ variant: "filled", color: "red" }}
                    topAdditonal={
                      <Text>
                        Workloads of <b>{item.issuer.name}</b> can no longer get
                        app tokens, and the users of its rules are removed. To
                        pause it instead, disable the issuer.
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
