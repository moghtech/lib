import { TrustedIssuerPage } from "mogh_ui";
import { useParams } from "react-router-dom";

/** The groups of the example, suggested for the groups of a rule. */
const GROUP_OPTIONS = ["deployers", "readers"];

/**
 * One trusted issuer (workload identity): mogh_ui's page, which the
 * settings' `TrustedIssuersTable` links to, as Komodo and Cicada mount
 * it.
 */
export default function TrustedIssuer() {
  const id = useParams().id as string;
  return (
    <TrustedIssuerPage
      id={id}
      backTo="/settings"
      groupOptions={GROUP_OPTIONS}
    />
  );
}
