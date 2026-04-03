import { Group } from "@mantine/core";
import { TriangleAlert } from "lucide-react";

export function UnsavedChanges({ fullWidth }: { fullWidth?: boolean }) {
  return (
    <Group
      gap="xs"
      wrap="nowrap"
      justify="space-evenly"
      w={fullWidth ? "100%" : "fit-content"}
    >
      <TriangleAlert size="1rem" />
      Unsaved changes
      <TriangleAlert size="1rem" />
    </Group>
  );
}
