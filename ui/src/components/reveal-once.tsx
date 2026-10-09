import { Button, Group, Stack, Text, TextInput } from "@mantine/core";
import { ArrowLeft, CircleCheckBig } from "lucide-react";
import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { CopyButton } from "./copy-button";

/** A value shown once, eg. a new secret or a recovery code. */
export type RevealedValue = {
  /**
   * Its row label, also the input's accessible name and what the copy
   * notification names.
   */
  label: string;
  value: string;
  /** Key material reads monospace. */
  monospace?: boolean;
};

/**
 * Set by a container (a popover, a modal) whose content may show a
 * value only once: a `RevealOnce` with `confirmSaved` calls it with
 * `true` while it shows one. The container then ignores what would
 * otherwise close it in passing (a click outside it, Escape, its own
 * toggle or close button), since closing unmounts the content and the
 * value with it: a private key or a secret would be gone for good.
 * Explicit buttons (Done) still close it.
 */
export const HoldOpen = createContext<(held: boolean) => void>(() => {});

/**
 * A container's side of `HoldOpen`: `held` while its content shows a
 * value only once. Render the content inside
 * `<HoldOpen.Provider value={setHeld}>`, and while `held` keep the
 * container open (eg. `closeOnClickOutside={!held}`,
 * `closeOnEscape={!held}`, a modal's `withCloseButton={!held}`).
 */
export function useHoldOpen() {
  const [held, setHeld] = useState(false);
  return { held, setHeld };
}

/**
 * What can only be shown once (a new secret, a private key, recovery
 * codes): each value in a read only input with a copy button, then
 * `Done`. Read only rather than disabled: the value stays selectable
 * for a manual copy (on a page served over plain http, where the
 * clipboard can't be written), and isn't greyed out.
 *
 * With `confirmSaved`, while values show the container holds open
 * (`HoldOpen`), and Done first asks whether they were saved, with a way
 * back to them. Without values (nothing secret to lose) Done closes at
 * once either way.
 */
export function RevealOnce({
  message,
  values,
  children,
  onDone,
  confirmSaved,
}: {
  /** Why to save it now: it can't be retrieved again. */
  message: ReactNode;
  values: RevealedValue[];
  /** Below the values: eg. how to use them. */
  children?: ReactNode;
  onDone: () => void;
  /**
   * Hold the container open (`HoldOpen`) while the values show, and
   * ask "Did you save it?" before Done closes. Default: false.
   */
  confirmSaved?: boolean;
}) {
  const hold = useContext(HoldOpen);
  const guarded = !!confirmSaved && values.length > 0;
  useEffect(() => {
    if (!guarded) return;
    hold(true);
    return () => hold(false);
  }, [hold, guarded]);
  const [confirming, setConfirming] = useState(false);

  if (confirming) {
    return (
      <Stack>
        <Text>
          Did you save {values.length > 1 ? "them" : "it"}? Once this closes, it
          can&apos;t be shown again.
        </Text>
        <Group justify="space-between">
          <Button
            variant="default"
            leftSection={<ArrowLeft size="1rem" />}
            onClick={() => setConfirming(false)}
          >
            Back
          </Button>
          <Button leftSection={<CircleCheckBig size="1rem" />} onClick={onDone}>
            Saved, close
          </Button>
        </Group>
      </Stack>
    );
  }

  return (
    <Stack>
      <Text>{message}</Text>
      {values.map(({ label, value, monospace }) => (
        <Group key={label} gap="sm" wrap="nowrap">
          <Text w={130} style={{ flexShrink: 0 }}>
            {label}
          </Text>
          <TextInput
            value={value}
            w="100%"
            readOnly
            aria-label={label}
            styles={
              monospace ? { input: { fontFamily: "monospace" } } : undefined
            }
          />
          <CopyButton content={value} label={label.toLowerCase()} />
        </Group>
      ))}
      {children}
      <Button
        leftSection={<CircleCheckBig size="1rem" />}
        onClick={guarded ? () => setConfirming(true) : onDone}
      >
        Done
      </Button>
    </Stack>
  );
}
