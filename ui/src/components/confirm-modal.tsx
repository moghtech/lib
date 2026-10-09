import {
  Button,
  ButtonProps,
  Group,
  Loader,
  Modal,
  ModalProps,
  Stack,
  Text,
  TextInput,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { ReactNode, useLayoutEffect, useState } from "react";
import { useSingleFlight } from "../hooks";
import { ConfirmButton } from "./confirm-button";
import { clipboardAvailable, copyToClipboard } from "./clipboard";

export interface ConfirmModalProps extends Omit<
  Omit<Omit<ModalProps, "opened">, "onClose">,
  "onClick"
> {
  children?: ReactNode;
  icon?: ReactNode;
  disabled?: boolean;
  /**
   * The text the user types to confirm, eg. the name of what is
   * deleted. Without it the click on the confirm button is enough.
   */
  confirmText?: string;
  title?: ReactNode;
  confirmButtonContent?: ReactNode;
  onConfirm?: () => Promise<unknown>;
  loading?: boolean;
  additional?: ReactNode;
  topAdditonal?: ReactNode;
  targetProps?: ButtonProps;
  targetNoIcon?: boolean;
  confirmProps?: ButtonProps;
  /** Converts into ConfirmButton (not with `opened`). */
  disableModal?: boolean;
  /**
   * Controls the dialog: it shows while `opened`, and renders no button
   * of its own, eg. for a dialog opened from a menu item (whose dropdown
   * unmounts on the click). Pass `onClose` with it, which is called to
   * close the dialog.
   */
  opened?: boolean;
  onClose?: () => void;
}

/**
 * A button opening a dialog, where the action is confirmed (by typing
 * `confirmText`, when given). Every open starts with an empty input:
 * text typed for an earlier open (confirmed or cancelled) doesn't
 * confirm the next. One confirm runs at a time: from the click until
 * `onConfirm` settled the confirm button waits and the dialog stays
 * open, then it closes, or stays open to retry when `onConfirm`
 * rejected (the failure was notified by whoever made the request, eg.
 * `useManageAuth`).
 */
export function ConfirmModal({
  children,
  icon,
  disabled,
  confirmText,
  title,
  confirmButtonContent,
  onConfirm,
  loading,
  additional,
  topAdditonal,
  targetProps,
  targetNoIcon,
  confirmProps,
  disableModal,
  opened: controlledOpened,
  onClose,
  ...modalProps
}: ConfirmModalProps) {
  const [openedHere, { open, close: closeHere }] = useDisclosure();
  const controlled = controlledOpened !== undefined;
  const opened = controlled ? controlledOpened : openedHere;
  const closeDialog = controlled ? () => onClose?.() : closeHere;
  const [input, setInput] = useState("");
  // The component (and its state) stays mounted while the dialog is
  // closed, eg. next to a container which can be restarted again: each
  // open starts over. Before the open paints: the text typed last time
  // would enable the confirm button for that frame.
  useLayoutEffect(() => {
    if (opened) setInput("");
  }, [opened]);

  const [pending, setPending] = useState(false);
  // `pending` lags a render behind a click: a second one (a double
  // click, a held Enter) would run the action again.
  const confirm = useSingleFlight(async () => {
    if (!onConfirm) return closeDialog();
    setPending(true);
    try {
      await onConfirm();
      closeDialog();
    } catch {
      // Stays open to retry; the failure was notified by whoever made
      // the request (eg. `useManageAuth`).
    } finally {
      setPending(false);
    }
  });
  const busy = loading || pending;

  if (disableModal && !controlled) {
    return (
      <ConfirmButton
        icon={icon}
        onClick={onConfirm}
        disabled={disabled}
        loading={loading}
        {...targetProps}
      >
        {children}
      </ConfirmButton>
    );
  }

  return (
    <>
      <Modal
        opened={opened}
        // The confirmed action runs on: the dialog closes once it
        // settled.
        onClose={() => pending || closeDialog()}
        title={
          <Text fz="h3">
            {title ?? (
              <>
                Confirm <b>{children}</b>
              </>
            )}
          </Text>
        }
        styles={{ content: { padding: "0.5rem" } }}
        size="lg"
        onClick={(e) => e.stopPropagation()}
        {...modalProps}
      >
        <Stack>
          {topAdditonal}

          {confirmText !== undefined && (
            <>
              <Text
                onClick={() => copyToClipboard(confirmText, "the confirm text")}
                style={{ cursor: "pointer" }}
              >
                Please enter <b>{confirmText}</b> below to confirm this action.
                {clipboardAvailable() && (
                  <Text fz="sm" c="dimmed">
                    You may click the text in bold to copy it
                  </Text>
                )}
              </Text>

              <TextInput
                value={input}
                onChange={(e) => setInput(e.target.value)}
                error={input === confirmText ? undefined : "Does not match"}
                aria-label={`Type ${confirmText} to confirm`}
              />
            </>
          )}

          {additional}

          <Group justify="end">
            <Button
              justify="space-between"
              w={{ base: "100%", xs: 190 }}
              miw="fit-content"
              rightSection={busy ? <Loader color="white" size="1rem" /> : icon}
              disabled={
                busy ||
                disabled ||
                (confirmText !== undefined && input !== confirmText)
              }
              onClick={(e) => {
                e.stopPropagation();
                confirm();
              }}
              {...confirmProps}
            >
              {confirmButtonContent ?? children}
            </Button>
          </Group>
        </Stack>
      </Modal>

      {!controlled && (
        <Button
          onClick={(e) => {
            e.stopPropagation();
            open();
          }}
          justify="space-between"
          w={{ base: "100%", xs: 190 }}
          miw="fit-content"
          rightSection={
            targetNoIcon ? undefined : busy ? (
              <Loader color="white" size="1rem" />
            ) : (
              icon
            )
          }
          loading={targetNoIcon ? busy : undefined}
          disabled={disabled || busy}
          {...targetProps}
        >
          {children}
        </Button>
      )}
    </>
  );
}
