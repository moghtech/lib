import { Text, Tooltip } from "@mantine/core";
import { type Expiry, expiryMs } from "../credential-key";
import { fmtTimeUntil } from "../formatting";
import { StatusBadge } from "./status-badge";

/** Time remaining until a credential expires, with the exact expiry
 * timestamp on hover; `Never` without one, `Expired` once past. */
export function ExpiresIn({ expires }: { expires: Expiry }) {
  const ms = expiryMs(expires);
  if (ms === null) {
    return (
      <Text c="dimmed" fz="sm">
        Never
      </Text>
    );
  }
  const remaining = ms - Date.now();
  return (
    <Tooltip label={new Date(ms).toLocaleString()} openDelay={200}>
      {remaining <= 0 ? (
        <StatusBadge text="Expired" intent="Critical" />
      ) : (
        <Text w="fit-content">{fmtTimeUntil(remaining)}</Text>
      )}
    </Tooltip>
  );
}
