import { Badge, Group, Switch, Table, Text } from "@mantine/core";
import {
  LoginProvidersTable,
  Page,
  Section,
  SupporterKeyConfig,
  TrustedIssuersTable,
} from "mogh_ui";
import { Settings as SettingsIcon, Users } from "lucide-react";
import { useInvalidate, useRead, useUser, useWrite } from "@/lib/hooks";

export default function Settings() {
  const user = useUser().data;
  if (!user?.admin) {
    return <Text>Only admins can change the settings.</Text>;
  }
  return (
    <Page title="Settings" icon={SettingsIcon}>
      <UsersTable ownId={user.id} />
      {/* Manages itself over the supporter api (admin only). */}
      <SupporterKeyConfig />
      {/* Both manage themselves over the auth api (admin only), each
          provider / issuer on its page. */}
      <LoginProvidersTable link={(id) => `/login-providers/${id}`} />
      <TrustedIssuersTable link={(id) => `/trusted-issuers/${id}`} />
    </Page>
  );
}

function UsersTable({ ownId }: { ownId: string }) {
  const users = useRead("ListUsers", {});
  const invalidate = useInvalidate();
  const { mutate: updateAccess } = useWrite("UpdateUserAccess", {
    onSuccess: () => invalidate(["ListUsers"]),
  });
  return (
    <Section
      title="Users"
      titleFz="h3"
      icon={<Users size="1.2rem" />}
      withBorder
      isPending={users.isPending}
    >
      <Table>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Username</Table.Th>
            <Table.Th>Logins</Table.Th>
            <Table.Th>Groups</Table.Th>
            <Table.Th>Enabled</Table.Th>
            <Table.Th>Admin</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {users.data?.map((user) => (
            <Table.Tr key={user.id} data-testid={`user-row-${user.username}`}>
              <Table.Td>
                <Group gap="xs">
                  <Text fw="bold">{user.username}</Text>
                  {user.workload && <Badge color="grape">Workload</Badge>}
                </Group>
              </Table.Td>
              <Table.Td>
                <Group gap="xs">
                  {user.has_password && <Badge color="gray">Local</Badge>}
                  {user.linked_logins.map((login) => (
                    <Badge key={login.provider_id} color="blue">
                      {login.provider_id}
                    </Badge>
                  ))}
                  {(user.totp_enrolled || user.passkey_enrolled) && (
                    <Badge color="green">2FA</Badge>
                  )}
                </Group>
              </Table.Td>
              <Table.Td>{user.groups.join(", ")}</Table.Td>
              <Table.Td>
                <Switch
                  aria-label={`${user.username} enabled`}
                  checked={user.enabled}
                  // A workload is disabled with its rule.
                  disabled={user.id === ownId || !!user.workload}
                  onChange={(e) =>
                    updateAccess({
                      user_id: user.id,
                      enabled: e.currentTarget.checked,
                    })
                  }
                />
              </Table.Td>
              <Table.Td>
                <Switch
                  aria-label={`${user.username} admin`}
                  checked={user.admin}
                  // The access of workloads is set by their rule.
                  disabled={user.id === ownId || !!user.workload}
                  onChange={(e) =>
                    updateAccess({
                      user_id: user.id,
                      admin: e.currentTarget.checked,
                    })
                  }
                />
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Section>
  );
}
