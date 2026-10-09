import { JSX, useState, ReactNode } from "react";
import {
  Alert,
  Badge,
  Group,
  NumberInput,
  PasswordInput,
  Stack,
  TagsInput,
  Text,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useQueryClient } from "@tanstack/react-query";
import { Info, ShieldAlert, Trash } from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";
import { Config, ConfigItem, configItemLabel } from "../../components/config";
import { ConfirmModal } from "../../components/confirm-modal";
import { CopyText } from "../../components/copy-text";
import { EntityHeader } from "../../components/entity-header";
import { EntityPage } from "../../components/entity-page";
import { InfoRow } from "../../components/info-row";
import { PageGuard } from "../../components/page-guard";
import { Section } from "../../components/section";
import { useExternalLoginProviders, useManageAuth } from "../hooks";
import { savedListItem } from "../list-cache";
import { LoginProviderIcon, LoginProviderKind } from "../login/providers";
import {
  ProviderFormValues,
  providerFormErrors,
  providerFormValues,
  providerUpdate,
} from "./values";

export const LOGIN_PROVIDER_KIND_LABELS = {
  Oidc: "OIDC",
  Github: "Github",
  Google: "Google",
} as const;

/** Stable components per kind, for the entity header's icon. */
const KIND_ICONS: Record<
  LoginProviderKind,
  (props: { size?: string | number }) => JSX.Element
> = {
  Oidc: ({ size }) => <LoginProviderIcon kind="Oidc" size={size} />,
  Github: ({ size }) => <LoginProviderIcon kind="Github" size={size} />,
  Google: ({ size }) => <LoginProviderIcon kind="Google" size={size} />,
};

/**
 * The page of one external login provider: its details and its
 * configuration, edited like an app's own entities (a config
 * section with a confirm / reset). For the app to mount at a
 * route of its own, eg. `/login-providers/:id`, and to link the
 * `LoginProvidersTable` to (its `link` prop).
 *
 * The API behind it is limited to admin users, see `AuthUserImpl::is_admin`.
 * Providers from the app configuration are shown read only.
 */
export function LoginProviderPage({
  id,
  backTo,
  onDeleted,
  children,
}: {
  /** The provider id (`ExternalLoginProvider.id`). */
  id: string;
  /** Where the back button (and a deletion) leads. */
  backTo: string;
  /** Called after the provider was deleted, before navigating back. */
  onDeleted?: () => void;
  /** Rendered below the configuration: what the app knows about the
   * provider, eg. its own audit logs of the logins through it. */
  children?: ReactNode;
}) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { data: providers, isPending, error } = useExternalLoginProviders();
  const item = providers?.find((item) => item.provider.id === id);

  // Set by the table right after creating the provider.
  const justCreated = !!(
    useLocation().state as { justCreated?: boolean } | null
  )?.justCreated;

  // The login page and linked logins show the enabled providers
  const invalidate = () =>
    Promise.all([
      queryClient.invalidateQueries({
        queryKey: ["ListExternalLoginProviders"],
      }),
      queryClient.invalidateQueries({ queryKey: ["GetLoginOptions"] }),
    ]);

  const { mutateAsync: update, isPending: updatePending } = useManageAuth(
    "UpdateExternalLoginProvider",
    {
      onSuccess: (saved) => {
        notifications.show({ message: "Saved login provider." });
        // Shown right away, the save resolving once the lists are current.
        return savedListItem(
          queryClient,
          ["ListExternalLoginProviders"],
          saved,
          (item) => item.provider.id,
          invalidate,
        );
      },
    },
  );
  const { mutateAsync: deleteProvider, isPending: deletePending } =
    useManageAuth("DeleteExternalLoginProvider", {
      onSuccess: () => {
        notifications.show({ message: "Deleted login provider." });
        invalidate();
        onDeleted?.();
        navigate(backTo);
      },
    });

  return (
    <PageGuard
      isPending={isPending}
      error={
        error
          ? (((error as any)?.result?.error as string | undefined) ??
            "Failed to load login providers")
          : !item
            ? "Login provider could not be found."
            : undefined
      }
    >
      {item && (
        <EntityPage backTo={backTo}>
          <EntityHeader
            name={item.provider.name}
            icon={KIND_ICONS[item.provider.config.kind]}
            intent={item.provider.config.params.enabled ? "Good" : "Warning"}
            state="Login Provider"
            status={
              LOGIN_PROVIDER_KIND_LABELS[item.provider.config.kind] +
              (item.read_only ? " · from the app configuration" : "")
            }
            onRename={
              item.read_only
                ? undefined
                : (name) =>
                    update(
                      providerUpdate(item, {
                        ...providerFormValues(item),
                        name,
                      }),
                    )
            }
            renamePending={updatePending}
            action={
              !item.read_only && (
                <ConfirmModal
                  icon={<Trash size="1rem" />}
                  confirmText={item.provider.name}
                  title="Delete Login Provider"
                  loading={deletePending}
                  onConfirm={() => deleteProvider({ id: item.provider.id })}
                  targetProps={{ w: "fit-content", variant: "default" }}
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
              )
            }
          />

          {justCreated && (
            <Alert icon={<Info size="1rem" />} color="green">
              Provider created. Register the redirect URI below at the provider,
              then enter the client id and secret it gives you and enable the
              provider.
            </Alert>
          )}

          <Section
            title="Details"
            icon={<Info size="1.3rem" />}
            description={
              item.read_only
                ? "This provider comes from the app configuration (file / environment), and can only be changed there."
                : "Users log in with this provider from the login page."
            }
          >
            <Stack gap="xs">
              <InfoRow label="Status" align="center">
                <Group gap="xs" wrap="nowrap">
                  <Badge
                    color={
                      item.provider.config.params.enabled ? "green.8" : "red"
                    }
                  >
                    {item.provider.config.params.enabled
                      ? "Enabled"
                      : "Disabled"}
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
                  {item.read_only ? (
                    <Badge
                      color="gray"
                      title="From the app configuration, read only"
                    >
                      Config
                    </Badge>
                  ) : (
                    <Badge color="blue">Managed</Badge>
                  )}
                </Group>
              </InfoRow>
              <InfoRow label="Redirect URI" align="center">
                <Stack gap="0.2rem">
                  <CopyText content={item.redirect_uri} label="redirect URI" />
                  <Text size="xs" c="dimmed">
                    Must be registered as an allowed redirect / callback URI at
                    the provider.
                  </Text>
                </Stack>
              </InfoRow>
              <InfoRow label="Provider ID" align="center">
                <CopyText content={item.provider.id} label="provider id" />
              </InfoRow>
            </Stack>
          </Section>

          <LoginProviderConfig
            // Reset the draft for another provider
            key={item.provider.id}
            item={item}
            onSave={async (values) => {
              await update(providerUpdate(item, values));
            }}
          />

          {children}
        </EntityPage>
      )}
    </PageGuard>
  );
}

type ListItem =
  ReturnType<typeof useExternalLoginProviders> extends {
    data: (infer I)[] | undefined;
  }
    ? I
    : never;

/**
 * The provider's configuration as a config section. The draft is
 * checked before it is saved (`providerFormErrors`): a refused save
 * says why, and from then on each field shows its error.
 */
function LoginProviderConfig({
  item,
  onSave,
}: {
  item: ListItem;
  onSave: (values: ProviderFormValues) => Promise<unknown>;
}) {
  const kind = item.provider.config.kind;
  const readOnly = item.read_only;
  const hasSecret = !!item.provider.config.params.client_secret;
  const original = providerFormValues(item);
  // Never persisted: the draft may hold the client secret.
  const [update, setUpdate] = useState<Partial<ProviderFormValues>>({});
  const values = { ...original, ...update };
  const errors = providerFormErrors(item, values);
  // Shown at the fields once a save was refused for them, not while
  // the draft is first filled in.
  const [showErrors, setShowErrors] = useState(false);
  const error = (field: keyof ProviderFormValues) =>
    showErrors ? errors[field] : undefined;
  const groupsUsed =
    !!values.groups_claim.trim() ||
    values.allowed_groups.length > 0 ||
    values.admin_groups.length > 0;

  // A list field, labelled after its key (ConfigItem spaces snake case).
  const tags =
    (
      field: keyof ProviderFormValues,
      description: string,
      placeholder: string,
      extra?: { maxTags?: number },
    ) =>
    (value: string[], set: (value: Partial<ProviderFormValues>) => void) => (
      <ConfigItem label={field} description={description}>
        <TagsInput
          value={value ?? []}
          onChange={(value) =>
            set({ [field]: value } as Partial<ProviderFormValues>)
          }
          placeholder={placeholder}
          disabled={readOnly}
          aria-label={configItemLabel(field)}
          w={{ base: "85%", lg: 400 }}
          {...extra}
        />
      </ConfigItem>
    );

  return (
    <Config
      title="Config"
      original={original}
      update={update}
      setUpdate={setUpdate}
      disabled={readOnly}
      // Never sent to the browser: the draft starts empty, whether a
      // secret is stored or not.
      secretKeys={[{ key: "client_secret", stored: hasSecret }]}
      onSave={async () => {
        const [message] = Object.values(errors);
        if (message) {
          setShowErrors(true);
          notifications.show({ message, color: "red" });
          throw new Error(message);
        }
        await onSave(values);
        setUpdate({});
      }}
      groups={{
        "": [
          {
            label: "General",
            labelHidden: true,
            fields: {
              enabled: {
                label: "Enabled",
                description: "Whether users can log in with this provider.",
              },
              slug: {
                label: "Slug",
                description:
                  "Names the provider in its login and redirect URIs (/auth/external/{slug}/callback). Lowercase letters, digits and hyphens, unique among the providers. Changing it changes the redirect URI to register at the provider.",
                placeholder: item.provider.slug ? undefined : item.provider.id,
                error: error("slug"),
              },
              registration_disabled: {
                label: "Disable new user registration",
                description:
                  "Only users who already have an account can log in with this provider.",
              },
            },
          },
          {
            label: "Client",
            labelHidden: true,
            fields: {
              provider: {
                label: "Provider URL",
                description:
                  "The issuer address, as reachable from the app server. It must serve /.well-known/openid-configuration.",
                placeholder: "https://accounts.example.com/application/o/app",
                hidden: kind !== "Oidc",
                error: error("provider"),
              },
              client_id: {
                label: "Client ID",
                description: "The client ID for the provider.",
                placeholder: "Enter client ID",
              },
              client_secret: (value, set) => (
                <ConfigItem
                  label="Client Secret"
                  description={
                    (kind === "Oidc"
                      ? "May be empty if the provider supports PKCE for public clients. "
                      : "") +
                    "Write-only: it is never returned by the API. Left empty, the stored secret is kept."
                  }
                >
                  <PasswordInput
                    value={value ?? ""}
                    onChange={(e) =>
                      set({ client_secret: e.currentTarget.value })
                    }
                    placeholder={
                      values.clear_client_secret
                        ? "Will be removed"
                        : hasSecret
                          ? "Unchanged"
                          : "Enter client secret"
                    }
                    autoComplete="new-password"
                    disabled={readOnly || values.clear_client_secret}
                    aria-label="Client Secret"
                    error={error("client_secret")}
                    w={{ base: "85%", lg: 400 }}
                  />
                </ConfigItem>
              ),
              clear_client_secret: {
                label: "Remove the stored client secret",
                description:
                  kind === "Oidc"
                    ? "For a provider switched to a public client using PKCE."
                    : "The provider has to be disabled, it can't work without a secret.",
                // Left empty the secret is kept, removing it has to be explicit
                hidden: !hasSecret,
                error: error("clear_client_secret"),
              },
            },
          },
          {
            hidden: kind !== "Oidc",
            label: "Groups",
            labelHidden: true,
            fields: {
              groups_claim: {
                label: "Groups Claim",
                description:
                  "The claim holding the user's groups. Nested claims use a dotted path, eg. realm_access.roles. Defaults to 'groups' when groups are used below.",
                placeholder: "groups",
              },
              allowed_groups: tags(
                "allowed_groups",
                "Only members of one of these groups (or an admin group) can log in. Empty allows everyone.",
                "Add group",
              ),
              admin_groups: (value, set) => (
                <Stack>
                  {tags(
                    "admin_groups",
                    "Members of these groups are made admins when they log in.",
                    "Add group",
                  )(value, set)}
                  {values.admin_groups.length > 0 && !readOnly && (
                    <Alert icon={<ShieldAlert size="1rem" />} color="yellow">
                      Anyone who controls membership of these groups at the
                      provider can make themselves an admin here.
                    </Alert>
                  )}
                </Stack>
              ),
              additional_scopes: tags(
                "additional_scopes",
                "Requested on top of openid, profile and email. The 'groups' scope is requested automatically when the provider advertises it." +
                  (groupsUsed
                    ? " Add the scope your provider needs for the groups claim if it is named differently."
                    : ""),
                "Add scope",
              ),
            },
          },
          {
            hidden: kind !== "Oidc",
            label: "Advanced",
            labelHidden: true,
            fields: {
              redirect_host: {
                label: "Redirect Host",
                description:
                  "The provider address users are redirected to in their browser, if it differs from the Provider URL. Host only, without a path.",
                placeholder: "https://accounts.example.com",
                error: error("redirect_host"),
              },
              additional_audiences: tags(
                "additional_audiences",
                "Audiences the provider sets on its tokens other than the client id.",
                "Add audience",
              ),
              use_full_email: {
                label: "Use full email as username",
                description:
                  "Otherwise new users are named after the part before the @.",
              },
              auto_redirect: {
                label: "Auto redirect",
                description:
                  "Send users straight to this provider instead of showing the login page. Add ?disableAutoLogin to the login URL to get the page back.",
              },
            },
          },
          {
            hidden: kind === "Github",
            label: "Token Exchange",
            labelHidden: true,
            fields: {
              token_exchange_enabled: {
                label: "Allow token exchange",
                description:
                  "Lets a client which already holds a token of a user from this provider (eg. a CLI or script) swap it for an app token at the token endpoint, without a browser login. Only for users who already exist.",
              },
              token_exchange_audiences: (value, set) =>
                values.token_exchange_enabled ? (
                  tags(
                    "token_exchange_audiences",
                    "Client ids of other apps at this provider whose tokens are accepted, in addition to the Client ID above.",
                    "Add client id",
                    // The server accepts at most 16
                    { maxTags: 16 },
                  )(value, set)
                ) : (
                  <></>
                ),
              token_exchange_max_age_secs: (value, set) =>
                values.token_exchange_enabled ? (
                  <Stack>
                    <ConfigItem
                      label="Maximum Token Age"
                      description="Only accept tokens issued at most this many seconds ago. 0 accepts them until they expire, which can be hours. Clients should exchange a token right after receiving it, so a few minutes (eg. 300) is enough."
                    >
                      <NumberInput
                        value={value}
                        // Emptied, the field is "": an error, not 0,
                        // which would accept tokens of any age.
                        onChange={(age) =>
                          set({
                            token_exchange_max_age_secs:
                              typeof age === "number" ? age : "",
                          })
                        }
                        suffix=" seconds"
                        min={0}
                        allowDecimal={false}
                        allowNegative={false}
                        disabled={readOnly}
                        aria-label="Maximum Token Age"
                        error={error("token_exchange_max_age_secs")}
                        w={{ base: "85%", lg: 400 }}
                      />
                    </ConfigItem>
                    {!readOnly && (
                      <Alert icon={<ShieldAlert size="1rem" />} color="yellow">
                        Anyone holding a valid token of a user can log in as
                        them without interaction
                        {values.token_exchange_audiences.length > 0
                          ? ", including tokens issued to every app listed above."
                          : "."}{" "}
                        Users who need a second factor for external logins can't
                        use it.
                      </Alert>
                    )}
                  </Stack>
                ) : (
                  <></>
                ),
            },
          },
        ],
      }}
    />
  );
}
