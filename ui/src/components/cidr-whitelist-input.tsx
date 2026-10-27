import {
  Button,
  Popover,
  Stack,
  TagsInput,
  TagsInputProps,
  Text,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { Pencil } from "lucide-react";
import { CSSProperties, ReactNode, useState } from "react";

/** The pills of a tags input on one scrolling line, so a long list
 * doesn't grow the input. */
const SCROLLING_PILLS = {
  pillsList: {
    flexWrap: "nowrap",
    overflowX: "auto",
    scrollbarWidth: "none",
  },
  pill: { flexShrink: 0 },
} satisfies Record<string, CSSProperties>;

export interface CidrWhitelistInputProps extends Omit<
  TagsInputProps,
  "data" | "value" | "onChange"
> {
  /** Absent on records typeshare marks optional (serde default). */
  value?: string[];
  onChange: (value: string[]) => void;
}

/** Free text entry of an ip list: CIDR ranges or bare ips (the
 * source ip whitelist of an api key, a signing key, a user). Entries
 * are validated server side (400 on an invalid one), so the input
 * only splits and trims. */
export function CidrWhitelistInput({
  value = [],
  onChange,
  ...props
}: CidrWhitelistInputProps) {
  return (
    <TagsInput
      placeholder={value.length ? "Add ip or CIDR" : "All ips allowed"}
      value={value}
      onChange={(value) =>
        onChange(value.map((entry) => entry.trim()).filter(Boolean))
      }
      splitChars={[",", " "]}
      styles={SCROLLING_PILLS}
      {...props}
    />
  );
}

/** The whitelist summarized in a table cell, with an inline popover
 * editor. The editor stays open until the save went through: a list
 * the server refuses (a malformed entry) is still there to fix. */
export function CidrWhitelistCell({
  value,
  onSave,
  description = "Source ips this key is accepted from, as CIDR ranges or bare ips. Empty allows all ips.",
}: {
  value: string[];
  /** Rejects when the save fails (the write's notification says
   * why). */
  onSave: (value: string[]) => Promise<unknown>;
  /** What the whitelist guards, above the editor. */
  description?: ReactNode;
}) {
  const [opened, { open, close }] = useDisclosure(false);
  const [draft, setDraft] = useState<string[]>(value);
  const [saving, setSaving] = useState(false);
  return (
    <Popover
      opened={opened}
      onChange={(opened) => (opened ? open() : close())}
      position="bottom-start"
      width={360}
      trapFocus
    >
      <Popover.Target>
        <Button
          variant="subtle"
          size="compact-sm"
          color={value.length ? undefined : "gray"}
          rightSection={<Pencil size="0.8rem" />}
          onClick={() => {
            setDraft(value);
            open();
          }}
        >
          {value.length ? value.join(", ") : "All ips"}
        </Button>
      </Popover.Target>
      <Popover.Dropdown onClick={(e) => e.stopPropagation()}>
        <Stack gap="sm">
          <Text fz="sm">{description}</Text>
          <CidrWhitelistInput value={draft} onChange={setDraft} autoFocus />
          <Button
            size="compact-sm"
            loading={saving}
            onClick={() => {
              setSaving(true);
              onSave(draft)
                .then(close, () => {})
                .finally(() => setSaving(false));
            }}
          >
            Save
          </Button>
        </Stack>
      </Popover.Dropdown>
    </Popover>
  );
}
