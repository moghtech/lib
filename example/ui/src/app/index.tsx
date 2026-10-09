import { AppShell, Button, Group, NavLink, Text } from "@mantine/core";
import {
  LoadingScreen,
  SupporterBadge,
  SupporterHomeButton,
  ThemeToggle,
  useSupporterBrand,
} from "mogh_ui";
import {
  Home,
  LogOut,
  NotebookText,
  Settings,
  User,
  Wrench,
} from "lucide-react";
import { Suspense } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { MoghAuth } from "example_client";
import { useUser, useUserInvalidate } from "@/lib/hooks";
import {
  RELEASE_DATE,
  SUPPORTER_APP,
  SUPPORTER_ROOT_KEYS,
} from "@/lib/supporter";

const PAGES = [
  { to: "/", label: "Home", icon: Home, admin: false },
  { to: "/notes", label: "Notes", icon: NotebookText, admin: false },
  { to: "/tools", label: "Tools", icon: Wrench, admin: false },
  { to: "/profile", label: "Profile", icon: User, admin: false },
  { to: "/settings", label: "Settings", icon: Settings, admin: true },
];

export default function App() {
  const user = useUser().data;
  const userInvalidate = useUserInvalidate();
  const { pathname } = useLocation();
  // The supporter key, verified in the browser once per page load, and
  // the branding of an organization's key: its icon on the badge, or
  // icon and name in place of the home button (`homeBrand`).
  const { supporter, branding, homeBrand } = useSupporterBrand({
    app: SUPPORTER_APP,
    releaseDate: RELEASE_DATE,
    rootKeys: SUPPORTER_ROOT_KEYS,
  });
  return (
    <AppShell
      header={{ height: 62 }}
      navbar={{ width: 220, breakpoint: 0 }}
      padding="lg"
    >
      <AppShell.Header>
        <Group h="100%" px="lg" justify="space-between" wrap="nowrap">
          {/* The home button, and next to it the supporter badge, or
              the offer to become one. */}
          <Group gap="xs" wrap="nowrap" miw={0}>
            {/* mogh_ui's, as in Komodo and Cicada: one variant here, the
                topbar has room for it at every width the suites use. */}
            <SupporterHomeButton
              brand={homeBrand}
              wordmark="Mogh Example"
              logo={<img src="/mogh-512x512.png" width={32} alt="" />}
              data-testid="home-button"
            />
            <SupporterBadge
              supporter={supporter}
              branding={branding}
              supportedText="Supporters fund the development of the Mogh apps, which stay free and open source."
              unsupportedText="The Mogh apps are free and open source, and every feature stays free. Supporters fund their development and get their name here."
            />
          </Group>
          <Group wrap="nowrap">
            <Text data-testid="current-user">{user?.username}</Text>
            <ThemeToggle />
            <Button
              variant="default"
              leftSection={<LogOut size="1rem" />}
              onClick={() => {
                if (user) MoghAuth.LOGIN_TOKENS.remove(user.id);
                userInvalidate();
                location.replace("/login");
              }}
            >
              Log Out
            </Button>
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar p="sm">
        {PAGES.filter((page) => !page.admin || user?.admin).map((page) => (
          <NavLink
            key={page.to}
            component={Link}
            to={page.to}
            label={page.label}
            leftSection={<page.icon size="1rem" />}
            active={pathname === page.to}
          />
        ))}
      </AppShell.Navbar>
      <AppShell.Main>
        <Suspense fallback={<LoadingScreen />}>
          <Outlet />
        </Suspense>
      </AppShell.Main>
    </AppShell>
  );
}
