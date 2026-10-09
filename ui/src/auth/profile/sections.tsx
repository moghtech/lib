import { ReactNode, useEffect, useState } from "react";
import {
  ActionIcon,
  Group,
  PasswordInput,
  Stack,
  Text,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { KeyRound, Lock, Save } from "lucide-react";
import { EnableSwitch } from "../../components/enable-switch";
import { Section } from "../../components/section";
import { useLoginOptions, useManageAuth } from "../hooks";
import { LinkedLogin, LinkedLogins } from "./linked-logins";
import { EnrollPasskey } from "./passkey";
import { EnrollTotp } from "./totp";

/** What the profile's auth sections show of the user. */
export interface AuthProfileUser {
  username: string;
  /** Whether the user has a local password. */
  passwordSet: boolean;
  totpEnrolled: boolean;
  passkeyEnrolled: boolean;
  /** Whether external logins skip the second factor. */
  externalSkip2fa: boolean;
  /** The external logins linked to the user. */
  linkedLogins: LinkedLogin[];
}

/**
 * The auth part of a profile page: "Login" (change the username, and
 * the password where local login is enabled), "Providers" (the linked
 * external logins, `LinkedLogins`) and "2FA" (passkey or TOTP, and
 * whether external logins skip it). Each app maps its user to
 * `AuthProfileUser` and puts its own sections (sessions, api keys,
 * ...) around these.
 */
export function AuthProfileSections({
  user,
  refetchUser,
  loginExtra,
}: {
  user: AuthProfileUser;
  /** Called after a change, to load the user again. */
  refetchUser: () => void;
  /**
   * The app's own part of the Login section, under the username and
   * password: eg. ending the user's sessions.
   */
  loginExtra?: ReactNode;
}) {
  const options = useLoginOptions().data;
  const [username, setUsername] = useState(user.username);
  // The saved name (or another tab's change) replaces the draft.
  useEffect(() => setUsername(user.username), [user.username]);
  const [password, setPassword] = useState("");
  const { mutate: updateUsername, isPending: usernamePending } = useManageAuth(
    "UpdateUsername",
    {
      onSuccess: () => {
        notifications.show({ message: "Username updated.", color: "green" });
        refetchUser();
      },
    },
  );
  const { mutate: updatePassword, isPending: passwordPending } = useManageAuth(
    "UpdatePassword",
    {
      onSuccess: () => {
        notifications.show({ message: "Password updated.", color: "green" });
        setPassword("");
        refetchUser();
      },
    },
  );
  const { mutate: updateExternalSkip2fa } = useManageAuth(
    "UpdateExternalSkip2fa",
    {
      onSuccess: () => {
        notifications.show({
          message: "External login skip 2fa mode updated.",
          color: "green",
        });
        refetchUser();
      },
    },
  );
  const secondFactor = user.totpEnrolled || user.passkeyEnrolled;

  return (
    <>
      <Section
        title="Login"
        titleFz="h3"
        icon={<KeyRound size="1.2rem" />}
        withBorder
      >
        <Stack gap="0">
          <Group>
            <Text ff="monospace">Username:</Text>
            <TextInput
              aria-label="Username"
              placeholder="Update username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              w={250}
            />
            <ActionIcon
              aria-label="Update Username"
              onClick={() => updateUsername({ username: username.trim() })}
              disabled={!username.trim() || username.trim() === user.username}
              loading={usernamePending}
            >
              <Save size="1rem" />
            </ActionIcon>
          </Group>

          {options?.local && (
            <Group mt="sm">
              <Text ff="monospace">Password:</Text>
              <PasswordInput
                aria-label="New Password"
                placeholder="Update password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                w={250}
              />
              <ActionIcon
                aria-label="Update Password"
                onClick={() => updatePassword({ password })}
                disabled={!password}
                loading={passwordPending}
              >
                <Save size="1rem" />
              </ActionIcon>
            </Group>
          )}

          {loginExtra}
        </Stack>
      </Section>

      <LinkedLogins
        refetchUser={refetchUser}
        passwordSet={user.passwordSet}
        linkedLogins={user.linkedLogins}
      />

      <Section
        title="2FA"
        titleFz="h3"
        icon={<Lock size="1.2rem" />}
        withBorder
      >
        <Group>
          <EnrollPasskey
            userInvalidate={refetchUser}
            passkeyEnrolled={user.passkeyEnrolled}
            totpEnrolled={user.totpEnrolled}
          />
          <EnrollTotp
            userInvalidate={refetchUser}
            passkeyEnrolled={user.passkeyEnrolled}
            totpEnrolled={user.totpEnrolled}
          />
          {secondFactor && (
            <EnableSwitch
              label="Skip 2FA for external logins"
              checked={user.externalSkip2fa}
              onCheckedChange={(external_skip_2fa) =>
                updateExternalSkip2fa({ external_skip_2fa })
              }
              // Off is the strict setting: nothing to warn about.
              redDisabled={false}
            />
          )}
        </Group>
      </Section>
    </>
  );
}
