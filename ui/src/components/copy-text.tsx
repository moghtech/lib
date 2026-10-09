import { Group, GroupProps, Text, TextProps } from "@mantine/core";
import { copyToClipboard } from "./clipboard";
import { CopyButton } from "./copy-button";

export interface CopyTextProps extends TextProps {
  content: string;
  label?: string;
  groupProps?: GroupProps;
}

export function CopyText({
  content,
  label,
  groupProps,
  ...textProps
}: CopyTextProps) {
  return (
    <Group gap="sm" wrap="nowrap" {...groupProps}>
      <Text
        title={content}
        w={{ base: 230, lg: 330 }}
        p="xs"
        bdrs="sm"
        style={{
          overflow: "hidden",
          whiteSpace: "nowrap",
          cursor: "pointer",
        }}
        className="text-ellipsis bordered-light"
        size="sm"
        onClick={() => copyToClipboard(content, label)}
        {...textProps}
      >
        {content}
      </Text>
      <CopyButton content={content} label={label} />
    </Group>
  );
}
