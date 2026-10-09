import { Center, Loader, Stack, Text, Title } from "@mantine/core";
import { useAuthState } from "mogh_ui";
import { lazy } from "react";
import {
  BrowserRouter,
  Navigate,
  Outlet,
  Route,
  Routes,
  useLocation,
} from "react-router-dom";
import { MoghAuth } from "example_client";
import { useUser } from "@/lib/hooks";
import App from "@/app";
import Login from "@/pages/login";

const Home = lazy(() => import("@/pages/home"));
const LoginProvider = lazy(() => import("@/pages/login-provider"));
const Notes = lazy(() => import("@/pages/notes"));
const Profile = lazy(() => import("@/pages/profile"));
const Settings = lazy(() => import("@/pages/settings"));
const Tools = lazy(() => import("@/pages/tools"));
const TrustedIssuer = lazy(() => import("@/pages/trusted-issuer"));

export const Router = () => {
  // Handles what an external login redirects back with:
  // redeeming the session for a token, or the second factor.
  const { jwt_redeem_ready, passkey_pending, totp } = useAuthState();

  if (jwt_redeem_ready) {
    return (
      <Center mt="30vh">
        <Loader size="xl" />
      </Center>
    );
  }

  if (passkey_pending || totp) {
    return <Login passkeyIsPending={passkey_pending} totpIsPending={totp} />;
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="login" element={<Login />} />
        <Route element={<RequireAuth />}>
          <Route path="/" element={<App />}>
            <Route path="" element={<Home />} />
            <Route path="notes" element={<Notes />} />
            <Route path="profile" element={<Profile />} />
            <Route path="settings" element={<Settings />} />
            <Route path="login-providers/:id" element={<LoginProvider />} />
            <Route path="trusted-issuers/:id" element={<TrustedIssuer />} />
            <Route path="tools" element={<Tools />} />
            <Route path="*" element={<Title order={3}>Page not found</Title>} />
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  );
};

const RequireAuth = () => {
  const { data: user, error } = useUser();
  const location = useLocation();

  // The client marks requests which never reached the server with
  // status 1. Logging in again wouldn't help with that.
  if ((error as { status?: number } | undefined)?.status === 1) {
    return (
      <Center mt="30vh">
        <Loader size="xl" />
      </Center>
    );
  }

  if (!MoghAuth.LOGIN_TOKENS.jwt() || error) {
    if (location.pathname === "/") {
      return <Navigate to="/login" replace />;
    }
    const backto = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?backto=${backto}`} replace />;
  }

  if (!user) {
    return (
      <Center mt="30vh">
        <Loader size="xl" />
      </Center>
    );
  }

  if (!user.enabled) {
    return (
      <Center mt="30vh">
        <Stack align="center">
          <Title order={3}>User not enabled</Title>
          <Text c="dimmed">An admin has to enable your user first.</Text>
        </Stack>
      </Center>
    );
  }

  return <Outlet />;
};
