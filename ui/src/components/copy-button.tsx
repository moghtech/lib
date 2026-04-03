import {
  ActionIcon,
  ActionIconProps,
  CopyButton as MantineCopyButton,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { Check, Copy } from "lucide-react";
import { ReactNode } from "react";

export interface CopyButtonProps {
  content: string;
  icon?: ReactNode;
  label?: string;
  size?: string | number;
  buttonSize?: ActionIconProps["size"];
}

export function CopyButton({
  content,
  icon,
  label = "content",
  size = "1.1rem",
  buttonSize = "lg",
}: CopyButtonProps) {
  return (
    <MantineCopyButton value={content}>
      {({ copied, copy }) => (
        <ActionIcon
          variant="default"
          onClick={(e) => {
            e.stopPropagation();
            copy();
            sendCopyNotification(label);
          }}
          size={buttonSize}
        >
          {copied ? <Check size={size} /> : (icon ?? <Copy size={size} />)}
        </ActionIcon>
      )}
    </MantineCopyButton>
  );
}

export function sendCopyNotification(label = "content") {
  if (location.origin.startsWith("https")) {
    notifications.show({
      message: `Copied ${label} to clipboard.`,
      color: "green",
    });
  } else {
    notifications.show({
      message: "Cannot copy to clipboard without HTTPS.",
      color: "red",
    });
  }
}
