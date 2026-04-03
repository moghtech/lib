import { Group, Stack, StackProps } from "@mantine/core";
import { ReactNode } from "react";
import { BackButton } from "./back-button";

export interface EntityPageProps extends StackProps {
  backTo?: string;
  actions?: ReactNode;
}

export function EntityPage({
  backTo,
  actions,
  children,
  ...props
}: EntityPageProps) {
  return (
    <Stack mb="50vh" {...props}>
      <Group justify="space-between">
        <BackButton to={backTo} />
        {actions && <Group wrap="nowrap">{actions}</Group>}
      </Group>
      {children}
    </Stack>
  );
}
