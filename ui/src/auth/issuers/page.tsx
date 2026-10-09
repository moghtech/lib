import { useState, ReactNode } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Group,
  NumberInput,
  Stack,
  Switch,
  TagsInput,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useQueryClient } from "@tanstack/react-query";
import {
  CircleMinus,
  Info,
  Plus,
  ServerCog,
  ShieldAlert,
  Trash,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import * as MoghAuth from "mogh_auth_client";
import { Config, ConfigItem } from "../../components/config";
import { ConfirmModal } from "../../components/confirm-modal";
import { CopyText } from "../../components/copy-text";
import { EnableSwitch } from "../../components/enable-switch";
import { EntityHeader } from "../../components/entity-header";
import { EntityPage } from "../../components/entity-page";
import { InfoRow } from "../../components/info-row";
import { PageGuard } from "../../components/page-guard";
import { Section } from "../../components/section";
import { useManageAuth, useTrustedIssuers } from "../hooks";
import { savedListItem } from "../list-cache";
import {
  IssuerFormValues,
  KEYS_SOURCES,
  RuleFormValues,
  issuerFormErrors,
  issuerFormValues,
  newRule,
  trustedIssuer,
} from "./values";

type ListItem = MoghAuth.Types.TrustedIssuerListItem;

/**
 * The page of one trusted issuer (workload identity): its details
 * and its configuration, rules included, edited like an app's own
 * entities (a config section with a confirm / reset). For the app
 * to mount at a route of its own, eg. `/trusted-issuers/:id`, and
 * to link the `TrustedIssuersTable` to (its `link` prop).
 *
 * The API behind it is limited to admin users, see `AuthUserImpl::is_admin`.
 * Issuers from the app configuration are shown read only.
 */
export function TrustedIssuerPage({
  id,
  backTo,
  groupOptions,
  onDeleted,
  children,
}: {
  /** The issuer id (`TrustedIssuer.id`). */
  id: string;
  /** Where the back button (and a deletion) leads. */
  backTo: string;
  /** The groups of the app, suggested for the groups of a rule. */
  groupOptions?: string[];
  /** Called after the issuer was deleted, before navigating back. */
  onDeleted?: () => void;
  /** Rendered below the configuration: what the app knows about the
   * issuer, eg. its own audit logs of the logins through it. */
  children?: ReactNode;
}) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { data: issuers, isPending, error } = useTrustedIssuers();
  const item = issuers?.find((item) => item.issuer.id === id);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["ListTrustedIssuers"] });

  const { mutateAsync: update, isPending: updatePending } = useManageAuth(
    "UpdateTrustedIssuer",
    {
      onSuccess: (saved) => {
        notifications.show({ message: "Saved trusted issuer." });
        // Shown right away, the save resolving once the list is current.
        return savedListItem(
          queryClient,
          ["ListTrustedIssuers"],
          saved,
          (item) => item.issuer.id,
          invalidate,
        );
      },
    },
  );
  const { mutateAsync: deleteIssuer, isPending: deletePending } = useManageAuth(
    "DeleteTrustedIssuer",
    {
      onSuccess: () => {
        notifications.show({ message: "Deleted trusted issuer." });
        invalidate();
        onDeleted?.();
        navigate(backTo);
      },
    },
  );

  const rules = item?.issuer.rules ?? [];
  const enabledRules = rules.filter((rule) => rule.enabled);

  return (
    <PageGuard
      isPending={isPending}
      error={
        error
          ? (((error as any)?.result?.error as string | undefined) ??
            "Failed to load trusted issuers")
          : !item
            ? "Trusted issuer could not be found."
            : undefined
      }
    >
      {item && (
        <EntityPage backTo={backTo}>
          <EntityHeader
            name={item.issuer.name}
            icon={ServerCog}
            intent={item.issuer.enabled ? "Good" : "Warning"}
            state="Trusted Issuer"
            status={
              item.read_only
                ? "Workload identity · from the app configuration"
                : "Workload identity"
            }
            onRename={
              item.read_only
                ? undefined
                : (name) =>
                    update({
                      issuer: trustedIssuer(item.issuer.id, {
                        ...issuerFormValues(item.issuer),
                        name,
                      }),
                    })
            }
            renamePending={updatePending}
            action={
              !item.read_only && (
                <ConfirmModal
                  icon={<Trash size="1rem" />}
                  confirmText={item.issuer.name}
                  title="Delete Trusted Issuer"
                  loading={deletePending}
                  onConfirm={() => deleteIssuer({ id: item.issuer.id })}
                  targetProps={{ w: "fit-content", variant: "default" }}
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
              )
            }
          />

          <Section
            title="Details"
            icon={<Info size="1.3rem" />}
            description={
              item.read_only
                ? "This issuer comes from the app configuration (file / environment), and can only be changed there."
                : "Machines whose platform token this issuer signed exchange it for an app token, as the user of the rule the token matches."
            }
          >
            <Stack gap="xs">
              <InfoRow label="Status" align="center">
                <Group gap="xs" wrap="nowrap">
                  <Badge color={item.issuer.enabled ? "green.8" : "red"}>
                    {item.issuer.enabled ? "Enabled" : "Disabled"}
                  </Badge>
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
              <InfoRow label="Issuer" align="center">
                <CopyText content={item.issuer.issuer} label="issuer" />
              </InfoRow>
              <InfoRow label="Signing keys">
                {KEYS_SOURCES.find(
                  (source) => source.value === item.issuer.keys?.source,
                )?.label ?? "Discovery"}
              </InfoRow>
              <InfoRow label="Rules" align="center">
                <Group gap="xs" wrap="nowrap">
                  <Text>
                    {enabledRules.length === rules.length
                      ? rules.length
                      : `${enabledRules.length} of ${rules.length} enabled`}
                  </Text>
                  {enabledRules.some((rule) => rule.admin) && (
                    <Badge color="yellow" title="A rule grants admin">
                      Admin
                    </Badge>
                  )}
                </Group>
              </InfoRow>
              <InfoRow label="Issuer ID" align="center">
                <CopyText content={item.issuer.id} label="issuer id" />
              </InfoRow>
            </Stack>
          </Section>

          <TrustedIssuerConfig
            // Reset the draft for another issuer
            key={item.issuer.id}
            item={item}
            groupOptions={groupOptions}
            onSave={async (values) => {
              await update({ issuer: trustedIssuer(item.issuer.id, values) });
            }}
          />

          {children}
        </EntityPage>
      )}
    </PageGuard>
  );
}

/**
 * The issuer's configuration as a config section, the rules edited
 * in place. The draft is checked before it is saved
 * (`issuerFormErrors`): a refused save says why, and from then on
 * each field shows its error.
 */
function TrustedIssuerConfig({
  item,
  groupOptions,
  onSave,
}: {
  item: ListItem;
  groupOptions?: string[];
  onSave: (values: IssuerFormValues) => Promise<unknown>;
}) {
  const readOnly = item.read_only;
  const original = issuerFormValues(item.issuer);
  const [update, setUpdate] = useState<Partial<IssuerFormValues>>({});
  const values = { ...original, ...update };
  const errors = issuerFormErrors(values);
  // Shown at the fields once a save was refused for them, not while
  // the draft is first filled in.
  const [showErrors, setShowErrors] = useState(false);
  const shown = showErrors ? errors : {};

  return (
    <Config
      title="Config"
      original={original}
      update={update}
      setUpdate={setUpdate}
      disabled={readOnly}
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
            fields: {
              enabled: {
                label: "Enabled",
                description:
                  "Whether tokens of this issuer are accepted at all.",
              },
            },
          },
          {
            label: "Tokens",
            labelHidden: true,
            fields: {
              issuer: {
                label: "Issuer",
                description:
                  "The issuer (iss) of the tokens, eg. https://token.actions.githubusercontent.com, or the issuer url of a Kubernetes cluster.",
                placeholder: "https://token.actions.githubusercontent.com",
                error: shown.issuer,
              },
              keys_source: {
                label: "Signing Keys",
                description:
                  "Discovery loads them from the issuer's /.well-known/openid-configuration (Github Actions, Gitlab, clusters exposing their discovery). Static keys are for issuers the app server can't reach, like most clusters.",
                options: KEYS_SOURCES,
              },
              keys_url: {
                label: "Keys URL",
                description:
                  "The url of the key set (JWKS), as reachable from the app server.",
                placeholder: "https://issuer.example.com/keys",
                hidden: values.keys_source !== "JwksUri",
                error: shown.keys_url,
              },
              keys_static: (value, set) =>
                values.keys_source === "Static" ? (
                  <ConfigItem
                    label="Static Keys"
                    description="The key set (JWKS json): kubectl get --raw /openid/v1/jwks. Has to be updated when the issuer rotates its keys."
                  >
                    <Textarea
                      value={value ?? ""}
                      onChange={(e) =>
                        set({ keys_static: e.currentTarget.value })
                      }
                      placeholder='{ "keys": [...] }'
                      autosize
                      minRows={3}
                      maxRows={12}
                      styles={{ input: { fontFamily: "monospace" } }}
                      disabled={readOnly}
                      aria-label="Static Keys"
                      error={shown.keys_static}
                      w={{ base: "100%", lg: 600 }}
                    />
                  </ConfigItem>
                ) : (
                  <></>
                ),
              audiences: (value, set) => (
                <ConfigItem
                  label="Audiences"
                  description="The audience (aud) the workload requests its token for. Use one specific to this app, like its url. The default audience of a platform is shared with every other service trusting it, and any of them could replay the tokens they receive."
                >
                  <TagsInput
                    value={value ?? []}
                    onChange={(audiences) => set({ audiences })}
                    placeholder="Add audience"
                    maxTags={16}
                    disabled={readOnly}
                    aria-label="Audiences"
                    error={shown.audiences}
                    w={{ base: "85%", lg: 400 }}
                  />
                </ConfigItem>
              ),
              max_token_age_secs: (value, set) => (
                <ConfigItem
                  label="Maximum Token Age"
                  description="Only accept tokens issued at most this many seconds ago. 0 accepts them until they expire."
                >
                  <NumberInput
                    value={value}
                    // Emptied, the field is "": an error, not 0,
                    // which would accept tokens of any age.
                    onChange={(age) =>
                      set({
                        max_token_age_secs: typeof age === "number" ? age : "",
                      })
                    }
                    suffix=" seconds"
                    min={0}
                    allowDecimal={false}
                    allowNegative={false}
                    disabled={readOnly}
                    aria-label="Maximum Token Age"
                    error={shown.max_token_age_secs}
                    w={{ base: "85%", lg: 400 }}
                  />
                </ConfigItem>
              ),
            },
          },
          {
            label: "Rules",
            description:
              "A token is accepted by the first enabled rule it meets all the claims of. Each rule has its own user, with the groups given here.",
            fields: {
              rules: (value, set) => (
                <RulesEditor
                  rules={value ?? []}
                  onChange={(rules) => set({ rules })}
                  readOnly={readOnly}
                  groupOptions={groupOptions}
                  errors={shown}
                />
              ),
            },
          },
        ],
      }}
    />
  );
}

/** The rules of an issuer, edited in place on a config draft. */
function RulesEditor({
  rules,
  onChange,
  readOnly,
  groupOptions,
  errors,
}: {
  rules: RuleFormValues[];
  onChange: (rules: RuleFormValues[]) => void;
  readOnly: boolean;
  groupOptions?: string[];
  /** The errors to show, by path (`issuerFormErrors`). */
  errors: Record<string, string>;
}) {
  const setRule = (index: number, changes: Partial<RuleFormValues>) =>
    onChange(
      rules.map((rule, r) => (r === index ? { ...rule, ...changes } : rule)),
    );
  return (
    <Stack>
      {rules.length === 0 && (
        <Text c="dimmed">No rules: the issuer accepts no token.</Text>
      )}
      {rules.map((rule, r) => (
        <Stack key={r} className="bordered-light" bdrs="md" p="md" gap="sm">
          <Group justify="space-between" align="end">
            <TextInput
              value={rule.name}
              onChange={(e) => setRule(r, { name: e.currentTarget.value })}
              label="Rule Name"
              description="Names the user of the rule"
              placeholder="eg. Deploy"
              disabled={readOnly}
              error={errors[`rules.${r}.name`]}
              style={{ flexGrow: 1 }}
            />
            <EnableSwitch
              checked={rule.enabled}
              onCheckedChange={(enabled) => setRule(r, { enabled })}
              disabled={readOnly}
              mb={6}
            />
            {!readOnly && (
              <ActionIcon
                color="red"
                variant="light"
                size="lg"
                mb={2}
                title="Remove rule"
                aria-label="Remove rule"
                onClick={() => onChange(rules.filter((_, i) => i !== r))}
              >
                <Trash size="1rem" />
              </ActionIcon>
            )}
          </Group>

          <Stack gap="0.3rem">
            <Text size="sm" fw={500}>
              Claims
            </Text>
            <Text size="xs" c="dimmed">
              All of them have to match. * matches any run of characters. Prefer
              claims which can't be changed or reused over names (eg. Github's
              repository_id over repository), and keep wildcards narrow. Nested
              claims use a dotted path, eg. kubernetes.io.namespace.
            </Text>
            {errors[`rules.${r}.claims`] && (
              <Text size="xs" c="red">
                {errors[`rules.${r}.claims`]}
              </Text>
            )}
            {rule.claims.map((condition, c) => (
              <Group key={c} gap="xs" wrap="nowrap" align="start">
                <TextInput
                  value={condition.claim}
                  onChange={(e) =>
                    setRule(r, {
                      claims: rule.claims.map((other, i) =>
                        i === c
                          ? { ...other, claim: e.currentTarget.value }
                          : other,
                      ),
                    })
                  }
                  placeholder="Claim, eg. sub"
                  aria-label="Claim"
                  disabled={readOnly}
                  error={errors[`rules.${r}.claims.${c}.claim`]}
                  style={{ flex: 1 }}
                />
                <TextInput
                  value={condition.pattern}
                  onChange={(e) =>
                    setRule(r, {
                      claims: rule.claims.map((other, i) =>
                        i === c
                          ? { ...other, pattern: e.currentTarget.value }
                          : other,
                      ),
                    })
                  }
                  placeholder="Value, eg. repo:my-org/my-repo:ref:refs/heads/main"
                  aria-label="Claim Value"
                  disabled={readOnly}
                  error={errors[`rules.${r}.claims.${c}.pattern`]}
                  style={{ flex: 2 }}
                />
                {!readOnly && (
                  <ActionIcon
                    color="red"
                    variant="subtle"
                    mt={4}
                    title="Remove claim"
                    aria-label="Remove claim"
                    onClick={() =>
                      setRule(r, {
                        claims: rule.claims.filter((_, i) => i !== c),
                      })
                    }
                  >
                    <CircleMinus size="1rem" />
                  </ActionIcon>
                )}
              </Group>
            ))}
            {!readOnly && (
              <Button
                variant="subtle"
                size="compact-sm"
                w="fit-content"
                leftSection={<Plus size="0.9rem" />}
                onClick={() =>
                  setRule(r, {
                    claims: [...rule.claims, { claim: "", pattern: "" }],
                  })
                }
              >
                Add claim
              </Button>
            )}
          </Stack>

          <TagsInput
            value={rule.groups}
            onChange={(groups) => setRule(r, { groups })}
            label="Groups"
            description="The groups of the rule's user, which decide what the workload can do"
            placeholder="Add group"
            data={groupOptions}
            disabled={readOnly}
          />

          <NumberInput
            value={rule.token_ttl_secs}
            // Emptied, the field is "": an error, not 0.
            onChange={(ttl) =>
              setRule(r, { token_ttl_secs: typeof ttl === "number" ? ttl : "" })
            }
            error={errors[`rules.${r}.token_ttl_secs`]}
            label="App Token Lifetime"
            description="How long the token given to the workload is valid. 0 and anything longer use the app default."
            suffix=" seconds"
            min={0}
            allowDecimal={false}
            allowNegative={false}
            disabled={readOnly}
          />

          <Switch
            checked={rule.admin}
            onChange={(e) => setRule(r, { admin: e.currentTarget.checked })}
            label="Admin"
            description="The rule's user is an admin"
            color="red"
            disabled={readOnly}
          />

          {rule.admin && !readOnly && (
            <Alert icon={<ShieldAlert size="1rem" />} color="yellow">
              Every workload matching this rule acts as an admin. Make sure its
              claims only match what you intend.
            </Alert>
          )}
        </Stack>
      ))}

      {!readOnly && (
        <Button
          variant="default"
          w="fit-content"
          leftSection={<Plus size="1rem" />}
          onClick={() => onChange([...rules, newRule()])}
        >
          Add rule
        </Button>
      )}
    </Stack>
  );
}
