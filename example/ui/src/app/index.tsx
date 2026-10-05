import {
  AppShell,
  Button,
  Group,
  NavLink,
  Text,
  Title,
} from "@mantine/core";
import {
  LoadingScreen,
  SupporterBadge,
  SupporterBrandIcon,
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
import { loginTokens, useUser, useUserInvalidate } from "@/lib/hooks";
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
  const homeIcon = homeBrand?.icon ? (
    <SupporterBrandIcon brand={homeBrand} />
  ) : undefined;
  // An icon which includes the name shows alone.
  const homeNameHidden = !!homeBrand?.hideName;
  return (
    <AppShell header={{ height: 62 }} navbar={{ width: 220, breakpoint: 0 }} padding="lg">
      <AppShell.Header>
        <Group h="100%" px="lg" justify="space-between" wrap="nowrap">
          {/* The home button, and next to it the supporter badge, or
              the offer to become one. */}
          <Group gap="xs" wrap="nowrap" miw={0}>
            <Button
              component={Link}
              to="/"
              variant="subtle"
              color="gray"
              px="xs"
              h="auto"
              py={4}
              leftSection={homeNameHidden ? undefined : homeIcon}
              aria-label={homeNameHidden ? homeBrand?.name : undefined}
              title={homeNameHidden ? homeBrand?.name : undefined}
              data-testid="home-button"
            >
              {homeNameHidden ? (
                homeIcon
              ) : (
                <Title
                  order={3}
                  // In capitals when an organization's branding says so.
                  tt={homeBrand?.uppercaseName ? "uppercase" : undefined}
                >
                  {homeBrand?.name ?? "Mogh Example"}
                </Title>
              )}
            </Button>
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
                const tokens = loginTokens();
                if (user) tokens.remove(user.id);
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
