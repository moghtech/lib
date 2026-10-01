import { Code, Stack, Text } from "@mantine/core";
import { Page, Section } from "mogh_ui";
import { Home as HomeIcon } from "lucide-react";
import { useRead, useUser } from "@/lib/hooks";

export default function Home() {
  const user = useUser().data;
  const info = useRead("GetCoreInfo", {}).data;
  const request = useRead("GetRequestInfo", {}).data;
  // Counted at most every few seconds on the server (mogh_cache).
  const stats = useRead("GetStats", {}, { refetchInterval: 5_000 }).data;
  return (
    <Page title="Home" icon={HomeIcon}>
      <Section title="You" withBorder>
        <Stack gap="xs">
          <Text data-testid="welcome">
            Logged in as <b>{user?.username}</b>
            {user?.admin ? " (admin)" : ""}
          </Text>
          <Text>
            Groups:{" "}
            <span data-testid="user-groups">
              {user?.groups.length ? user.groups.join(", ") : "none"}
            </span>
          </Text>
          <Text>
            Your ip, as the server sees it: <Code>{request?.ip}</Code> (
            {request?.auth_method})
          </Text>
        </Stack>
      </Section>
      <Section title="Server" withBorder>
        <Stack gap="xs">
          <Text>
            {info?.app_name} at <Code>{info?.host}</Code>
          </Text>
          <Text data-testid="stats">
            {stats?.users ?? "-"} users, {stats?.notes ?? "-"} notes,{" "}
            {stats?.api_keys ?? "-"} api keys
          </Text>
        </Stack>
      </Section>
    </Page>
  );
}
