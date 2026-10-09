import { LoginProviderPage } from "mogh_ui";
import { useParams } from "react-router-dom";

/**
 * One external login provider: mogh_ui's page, which the settings'
 * `LoginProvidersTable` links to, as Komodo and Cicada mount it.
 */
export default function LoginProvider() {
  const id = useParams().id as string;
  return <LoginProviderPage id={id} backTo="/settings" />;
}
