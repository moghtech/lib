import { ActionIcon, ActionIconProps } from "@mantine/core";
import { Check, Copy } from "lucide-react";
import { ReactNode, useEffect, useState } from "react";
import { copyToClipboard } from "./clipboard";

export interface CopyButtonProps {
  content: string;
  icon?: ReactNode;
  /** What is copied, in the notification and the button's label. */
  label?: string;
  size?: string | number;
  buttonSize?: ActionIconProps["size"];
}

/**
 * Copies `content` (`copyToClipboard`): the check mark and the
 * notification follow what the browser did, so a page which can't
 * copy (plain http) says so rather than "Copied".
 */
export function CopyButton({
  content,
  icon,
  label = "content",
  size = "1.1rem",
  buttonSize = "lg",
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timeout = setTimeout(() => setCopied(false), 1_000);
    return () => clearTimeout(timeout);
  }, [copied]);
  return (
    <ActionIcon
      variant="default"
      onClick={(e) => {
        e.stopPropagation();
        copyToClipboard(content, label).then(setCopied);
      }}
      size={buttonSize}
      aria-label={`Copy ${label}`}
    >
      {copied ? <Check size={size} /> : (icon ?? <Copy size={size} />)}
    </ActionIcon>
  );
}
