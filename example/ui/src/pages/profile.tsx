import {
  ActionIcon,
  Badge,
  Button,
  Code,
  Group,
  Modal,
  SegmentedControl,
  Stack,
  Table,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  AuthProfileSections,
  CopyButton,
  Page,
  Section,
  useManageAuth,
} from "mogh_ui";
import { KeyRound, Plus, Trash, User } from "lucide-react";
import { useState } from "react";
import { Types } from "example_client";
import {
  useInvalidate,
  useRead,
  useUser,
  useUserInvalidate,
  useWrite,
} from "@/lib/hooks";

export default function Profile() {
  const user = useUser().data;
  const refetchUser = useUserInvalidate();
  if (!user) return null;
  return (
    <Page title="Profile" icon={User}>
      {/* Login, linked providers and 2FA: mogh_ui's, as in Komodo and
          Cicada. */}
      <AuthProfileSections
        user={{
          username: user.username,
          passwordSet: user.has_password,
          totpEnrolled: user.totp_enrolled,
          passkeyEnrolled: user.passkey_enrolled,
          externalSkip2fa: user.external_skip_2fa,
          linkedLogins: user.linked_logins,
        }}
        refetchUser={refetchUser}
      />

      <ApiKeys />

      <CidrWhitelist
        key={user.cidr_whitelist.join(",")}
        current={user.cidr_whitelist}
        refetchUser={refetchUser}
      />
    </Page>
  );
}

const KEY_KIND_LABEL: Record<Types.ApiKeyKind, string> = {
  [Types.ApiKeyKind.ApiKey]: "Api Key",
  [Types.ApiKeyKind.SigningKey]: "Signing Key",
};

function ApiKeys() {
  const keys = useRead("ListApiKeys", {});
  const invalidate = useInvalidate();
  const [open, setOpen] = useState(false);
  const onDeleted = () => {
    invalidate(["ListApiKeys"], ["GetStats"]);
    notifications.show({ message: "Api key deleted.", color: "green" });
  };
  const { mutate: deleteKey } = useManageAuth("DeleteApiKey", {
    onSuccess: onDeleted,
  });
  const { mutate: deleteSigningKey } = useManageAuth("DeleteSigningKey", {
    onSuccess: onDeleted,
  });
  return (
    <Section
      title="Api Keys"
      titleFz="h3"
      icon={<KeyRound size="1.2rem" />}
      withBorder
      actions={
        <Button
          leftSection={<Plus size="1rem" />}
          onClick={() => setOpen(true)}
        >
          New Api Key
        </Button>
      }
    >
      {keys.data?.length === 0 && <Text c="dimmed">No api keys.</Text>}
      <Table>
        <Table.Tbody>
          {keys.data?.map((key) => (
            <Table.Tr key={key.key} data-testid="api-key-row">
              <Table.Td>
                <Text fw="bold">{key.name}</Text>
              </Table.Td>
              <Table.Td>
                <Badge>{KEY_KIND_LABEL[key.kind]}</Badge>
              </Table.Td>
              <Table.Td>
                <Code>{key.key.slice(0, 16)}...</Code>
              </Table.Td>
              <Table.Td>
                <Text size="sm" c="dimmed">
                  {key.expires
                    ? `Expires ${new Date(key.expires).toLocaleString()}`
                    : "Never expires"}
                </Text>
              </Table.Td>
              <Table.Td>
                <Group justify="end">
                  <ActionIcon
                    color="red"
                    aria-label={`Delete api key ${key.name}`}
                    onClick={() =>
                      key.kind === Types.ApiKeyKind.ApiKey
                        ? deleteKey({ key: key.key })
                        : deleteSigningKey({ public_key: key.key })
                    }
                  >
                    <Trash size="1rem" />
                  </ActionIcon>
                </Group>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
      <NewApiKeyModal opened={open} onClose={() => setOpen(false)} />
    </Section>
  );
}

function NewApiKeyModal({
  opened,
  onClose,
}: {
  opened: boolean;
  onClose: () => void;
}) {
  const invalidate = useInvalidate();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<Types.ApiKeyKind>(Types.ApiKeyKind.ApiKey);
  // Shown once, the server doesn't keep them.
  const [created, setCreated] = useState<{ label: string; value: string }[]>();
  const onSuccess = () => invalidate(["ListApiKeys"], ["GetStats"]);
  const { mutate: create } = useManageAuth("CreateApiKey", {
    onSuccess: ({ key, secret }) => {
      onSuccess();
      setCreated([
        { label: "Key", value: key },
        { label: "Secret", value: secret },
      ]);
    },
  });
  const { mutate: createSigningKey } = useManageAuth("CreateSigningKey", {
    onSuccess: ({ private_key }) => {
      onSuccess();
      setCreated([{ label: "Private Key", value: private_key ?? "" }]);
    },
  });
  const close = () => {
    setCreated(undefined);
    setName("");
    onClose();
  };
  return (
    <Modal opened={opened} onClose={close} title="New Api Key" size="lg">
      {created ? (
        <Stack>
          <Text>Save these now, they can't be shown again.</Text>
          {created.map(({ label, value }) => (
            <Group key={label} wrap="nowrap">
              <Text w={90}>{label}</Text>
              <Code
                data-testid={`api-key-${label.toLowerCase().replace(" ", "-")}`}
                style={{ wordBreak: "break-all" }}
              >
                {value}
              </Code>
              <CopyButton content={value} />
            </Group>
          ))}
          <Group justify="end">
            <Button onClick={close}>Done</Button>
          </Group>
        </Stack>
      ) : (
        <Stack>
          <TextInput
            label="Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            data-autofocus
          />
          <SegmentedControl
            value={kind}
            onChange={(kind) => setKind(kind as Types.ApiKeyKind)}
            data={[
              { value: Types.ApiKeyKind.ApiKey, label: "Key + Secret" },
              {
                value: Types.ApiKeyKind.SigningKey,
                label: "Signing Key (key pair)",
              },
            ]}
          />
          <Group justify="end">
            <Button
              disabled={!name}
              onClick={() =>
                kind === Types.ApiKeyKind.ApiKey
                  ? create({ name, expires: 0, cidr_whitelist: [] })
                  : createSigningKey({
                      name,
                      expires: 0,
                      cidr_whitelist: [],
                      public_key: "",
                    })
              }
            >
              Create
            </Button>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}

function CidrWhitelist({
  current,
  refetchUser,
}: {
  current: string[];
  refetchUser: () => void;
}) {
  const [value, setValue] = useState(current.join("\n"));
  const { mutate, isPending } = useWrite("UpdateCidrWhitelist", {
    onSuccess: () => {
      notifications.show({ message: "Whitelist updated.", color: "green" });
      refetchUser();
    },
  });
  return (
    <Section
      title="Ip Whitelist"
      titleFz="h3"
      description="CIDR ranges or ips you can log in / call the api from, one per line. Empty allows all. ⚠️ Leaving out your own ip locks you out."
      withBorder
    >
      <Textarea
        aria-label="Ip Whitelist"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="10.0.0.0/8"
        autosize
        minRows={2}
        maw={400}
      />
      <Group>
        <Button
          variant="default"
          loading={isPending}
          onClick={() =>
            mutate({
              cidr_whitelist: value
                .split("\n")
                .map((line) => line.trim())
                .filter(Boolean),
            })
          }
        >
          Save Whitelist
        </Button>
      </Group>
    </Section>
  );
}
