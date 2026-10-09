import {
  ActionIcon,
  Box,
  Button,
  Divider,
  Flex,
  Group,
  Menu,
  Stack,
  Text,
} from "@mantine/core";
import {
  ArrowLeftRight,
  Circle,
  LogOut,
  Plus,
  Settings,
  User,
} from "lucide-react";
import * as MoghAuth from "mogh_auth_client";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { hexColorByIntention } from "../color";
import { addAccountPath, currentUserId, useAccounts } from "./accounts";

/** How the menu shows an account. */
export interface AccountInfo {
  username: string;
  /** An image url. Without it, a user icon. */
  avatar?: string;
}

export interface AccountsMenuProps {
  /**
   * This tab's user, from the app's own session query (`undefined`
   * while it loads): its id, and how the menu's button shows it.
   */
  user: (AccountInfo & { id: string }) | undefined;
  /**
   * How the menu shows another signed in user, eg. from the app's
   * `GetUsername`: `undefined` while unknown (the account isn't
   * listed until then). A React hook, called once in each account's
   * row: pass a hook defined at module level.
   */
  useAccountInfo: (userId: string) => AccountInfo | undefined;
  /**
   * The app's cleanup for users signed out here (one account, or all
   * of them), called after their tokens are removed: eg. what it keeps
   * for them in `localStorage`. When this tab's user is among them the
   * page is reloaded afterwards, which drops everything cached for the
   * user and leads to the login page.
   */
  onSignOut?: (userIds: string[]) => void;
  /** Where the Profile button leads. Default `/profile`. */
  profilePath?: string;
}

/**
 * The topbar's account menu: this tab's user as its button, and in it
 * every signed in account (switch to it, or sign it out, in every tab),
 * "Add Account" (`addAccountPath`: the login page, without its auto
 * redirect, back here after), the profile, and "Log Out All".
 *
 * Switching accounts reloads the page with the other user. The tokens
 * are shared by the tabs (`MoghAuth.LOGIN_TOKENS`), and the list
 * follows sign ins / outs in other tabs.
 */
export function AccountsMenu({
  user,
  useAccountInfo,
  onSignOut,
  profilePath = "/profile",
}: AccountsMenuProps) {
  const [viewLogout, setViewLogout] = useState(false);
  const [open, _setOpen] = useState(false);
  const setOpen = (open: boolean) => {
    _setOpen(open);
    if (open) {
      setViewLogout(false);
    }
  };
  // Kept up to date with sign ins / outs in any tab.
  const accounts = useAccounts();
  const nav = useNavigate();
  /** Signs `userIds` out (in every tab) with `remove`. */
  const signOut = (userIds: string[], remove: () => void) => {
    // This tab's user as the store knows it, also before the app's
    // session query loaded it.
    const current = currentUserId();
    remove();
    onSignOut?.(userIds);
    if (current !== undefined && userIds.includes(current)) {
      location.reload();
    }
  };
  return (
    <Menu offset={13} opened={open} onChange={setOpen}>
      <Menu.Target>
        <Button
          variant="subtle"
          size="lg"
          leftSection={<Avatar avatar={user?.avatar} size="1.1rem" />}
          pl="0.7rem"
          pr={{ base: "-20", lg: "0.7rem" }}
          aria-label={user ? `Account: ${user.username}` : "Account"}
        >
          <Username username={user?.username} />
        </Button>
      </Menu.Target>
      <Menu.Dropdown w={350} maw="96vw">
        <Stack gap="xs" m="xs" mt="0.3rem" mb="0.3rem">
          <Group justify="space-between">
            <Group opacity={0.8} fz="sm" lh="sm">
              <ArrowLeftRight size="1rem" />
              Switch accounts
            </Group>
            <ActionIcon
              variant={viewLogout ? "filled" : "subtle"}
              c="inherit"
              onClick={() => setViewLogout((l) => !l)}
              aria-label="Log out accounts"
              aria-pressed={viewLogout}
            >
              <LogOut size="1rem" />
            </ActionIcon>
          </Group>

          <Divider />

          {accounts.map((login) => (
            <Account
              key={login.user_id}
              userId={login.user_id}
              selected={login.user_id === user?.id}
              useAccountInfo={useAccountInfo}
              close={() => setOpen(false)}
              signOut={signOut}
              viewLogout={viewLogout}
            />
          ))}

          <Divider />

          <Group grow>
            <Button
              variant="subtle"
              c="inherit"
              leftSection={<Plus size="1rem" />}
              onClick={() => {
                setOpen(false);
                nav(addAccountPath());
              }}
            >
              <Box component="span">
                Add
                <Box component="span" pl="0.25rem" visibleFrom="xs">
                  Account
                </Box>
              </Box>
            </Button>

            <Button
              leftSection={<Settings size="1rem" />}
              onClick={() => {
                setOpen(false);
                nav(profilePath);
              }}
            >
              Profile
            </Button>
          </Group>

          {viewLogout && (
            <Button
              variant="filled"
              color="red"
              rightSection={<LogOut size="1rem" />}
              fullWidth
              onClick={() =>
                signOut(
                  // Read now: also the accounts signed in by another tab
                  // since this rendered.
                  MoghAuth.LOGIN_TOKENS.accounts().map(
                    (account) => account.user_id,
                  ),
                  MoghAuth.LOGIN_TOKENS.remove_all,
                )
              }
            >
              Log Out All
            </Button>
          )}
        </Stack>
      </Menu.Dropdown>
    </Menu>
  );
}

function Account({
  userId,
  selected,
  useAccountInfo,
  close,
  signOut,
  viewLogout,
}: {
  userId: string;
  selected: boolean;
  useAccountInfo: (userId: string) => AccountInfo | undefined;
  close: () => void;
  signOut: (userIds: string[], remove: () => void) => void;
  viewLogout: boolean;
}) {
  const info = useAccountInfo(userId);
  if (!info) return null;
  return (
    <Flex align="center" gap="md" w="100%">
      <Button
        variant={selected ? "default" : "subtle"}
        rightSection={
          <Circle
            stroke="none"
            fill={hexColorByIntention("Good")}
            size="0.8rem"
            style={{ display: selected ? undefined : "none" }}
          />
        }
        justify="space-between"
        fullWidth
        aria-current={selected || undefined}
        onClick={() => {
          if (selected) {
            close();
            return;
          }
          MoghAuth.LOGIN_TOKENS.change(userId);
          location.reload();
        }}
      >
        <Avatar
          avatar={info.avatar}
          size="1.1rem"
          style={{ marginRight: "0.5rem" }}
        />
        <Username username={info.username} alwaysShowUsername />
      </Button>

      {viewLogout && (
        <ActionIcon
          color="red"
          aria-label={`Log out ${info.username}`}
          // Signs the user out in every tab. Another account than this
          // tab's leaves the list on its own (`useAccounts`).
          onClick={() =>
            signOut([userId], () => MoghAuth.LOGIN_TOKENS.remove(userId))
          }
        >
          <LogOut size="1rem" />
        </ActionIcon>
      )}
    </Flex>
  );
}

function Avatar({
  avatar,
  size,
  style,
}: {
  avatar: string | undefined;
  size: string;
  style?: React.CSSProperties;
}) {
  return avatar ? (
    <img
      src={avatar}
      alt=""
      // The avatar host (eg. a login provider's) learns nothing of the app.
      referrerPolicy="no-referrer"
      style={{ width: size, height: size, ...style }}
    />
  ) : (
    <User size="1.3rem" style={style} />
  );
}

function Username({
  username,
  alwaysShowUsername,
}: {
  username: string | undefined;
  alwaysShowUsername?: boolean;
}) {
  return (
    <Text
      style={{
        overflow: "hidden",
        textOverflow: "ellipsis",
        maxWidth: 140,
      }}
      visibleFrom={alwaysShowUsername ? undefined : "lg"}
    >
      {username}
    </Text>
  );
}
