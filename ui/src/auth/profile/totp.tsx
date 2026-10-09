import {
  Alert,
  Button,
  Center,
  Flex,
  Group,
  Loader,
  Modal,
  Stack,
  Text,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { Check, Copy, RotateCcwKey, Trash } from "lucide-react";
import { useState } from "react";
import { copyToClipboard } from "../../components/clipboard";
import { ConfirmModal } from "../../components/confirm-modal";
import { CopyButton } from "../../components/copy-button";
import {
  HoldOpen,
  RevealOnce,
  useHoldOpen,
} from "../../components/reveal-once";
import { errorNotificationMessage } from "../../errors";
import { useManageAuth } from "../hooks";

export const EnrollTotp = ({
  userInvalidate,
  passkeyEnrolled,
  totpEnrolled,
}: {
  userInvalidate?: () => void;
  passkeyEnrolled?: boolean;
  totpEnrolled?: boolean;
}) => {
  const [open, setOpen] = useState(false);
  const [submitted, setSubmitted] = useState<{ uri: string; png: string }>();
  const [confirm, setConfirm] = useState("");
  const [recovery, setRecovery] = useState<string[] | undefined>(undefined);
  // Kept here: the request (and its error) is forgotten once it settled.
  const [beginError, setBeginError] = useState<unknown>();
  // While the recovery codes show: they can't be shown again.
  const { held, setHeld } = useHoldOpen();

  const { mutate: beginEnrollment } = useManageAuth("BeginTotpEnrollment", {
    onSuccess: ({ uri, png }) => setSubmitted({ uri, png }),
    onError: (e) => setBeginError(e),
  });
  const begin = () => {
    setBeginError(undefined);
    beginEnrollment({});
  };

  const { mutate: confirmEnrollment, isPending: confirmPending } =
    useManageAuth("ConfirmTotpEnrollment", {
      onSuccess: ({ recovery_codes }) => {
        setRecovery(recovery_codes);
        userInvalidate?.();
      },
    });

  const { mutateAsync: unenroll, isPending: unenrollPending } = useManageAuth(
    "UnenrollTotp",
    {
      onSuccess: () => {
        userInvalidate?.();
        notifications.show({
          message: "Unenrolled in TOTP 2FA.",
          color: "green",
        });
      },
    },
  );

  const onOpenChange = (open: boolean) => {
    setOpen(open);
    if (open) {
      // Each open starts over: a code typed for an earlier enrollment
      // is no code of this one.
      setConfirm("");
      begin();
    } else {
      setSubmitted(undefined);
      setRecovery(undefined);
      setBeginError(undefined);
    }
  };

  return (
    <>
      {/* Not part of the 'not enrolled' branch below: confirming the
          enrollment refreshes the user, and the recovery codes have to
          stay on screen after the user counts as enrolled. */}
      <Modal
        opened={open}
        onClose={() => onOpenChange(false)}
        title={recovery ? "Save recovery keys" : "Enroll TOTP 2FA"}
        size="lg"
        // A stray click or Escape doesn't lose the recovery codes.
        closeOnClickOutside={!held}
        closeOnEscape={!held}
        withCloseButton={!held}
      >
        <HoldOpen.Provider value={setHeld}>
          {recovery && (
            <RevealOnce
              message="Each logs in once in place of a code from the authenticator app. They can't be shown again."
              values={recovery.map((code, i) => ({
                label: `Code ${i + 1}`,
                value: code,
                monospace: true,
              }))}
              onDone={() => onOpenChange(false)}
              confirmSaved
            >
              <Button
                variant="default"
                leftSection={<Copy size="1rem" />}
                onClick={() =>
                  copyToClipboard(recovery.join("\n"), "the recovery codes")
                }
              >
                Copy All
              </Button>
            </RevealOnce>
          )}
          {!recovery && submitted && (
            <Flex direction="column" gap="lg">
              <Text size="lg">
                Scan this QR code with your authenticator app, and enter the 6
                digit code below.
              </Text>
              <Center>
                <img
                  width={250}
                  height={250}
                  src={"data:image/png;base64," + submitted.png}
                  alt="QRCode"
                />
              </Center>
              <Flex align="center" justify="space-between" gap="sm">
                URI
                {/* Read only: selectable for a manual copy where the
                  clipboard can't be written (plain http). */}
                <TextInput
                  w={250}
                  value={submitted.uri}
                  readOnly
                  aria-label="URI"
                />
                <CopyButton content={submitted.uri} label="the URI" />
              </Flex>
              <Flex align="center" justify="space-between">
                Confirm Code
                <TextInput
                  w={250}
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  aria-label="Confirm Code"
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  autoFocus
                />
              </Flex>
              <Flex justify="flex-end">
                <Button
                  onClick={() => confirmEnrollment({ code: confirm })}
                  disabled={confirm.length !== 6 || confirmPending}
                  leftSection={<Check size="1rem" />}
                  loading={confirmPending}
                >
                  Confirm
                </Button>
              </Flex>
            </Flex>
          )}
          {!recovery &&
            !submitted &&
            (beginError ? (
              // Eg. a recent login required, or rate limited: not a
              // loader which never ends.
              <Stack>
                <Alert color="red" title="The enrollment could not begin">
                  {errorNotificationMessage(beginError)}
                </Alert>
                <Group justify="flex-end">
                  <Button variant="default" onClick={begin}>
                    Try Again
                  </Button>
                </Group>
              </Stack>
            ) : (
              <Center>
                <Loader />
              </Center>
            ))}
        </HoldOpen.Provider>
      </Modal>
      {!totpEnrolled && !passkeyEnrolled && (
        <Button
          leftSection={<RotateCcwKey size="1rem" />}
          variant="default"
          onClick={() => onOpenChange(true)}
          w={220}
        >
          Enroll TOTP 2FA
        </Button>
      )}
      {totpEnrolled && (
        <ConfirmModal
          confirmText="Unenroll"
          icon={<Trash size="1rem" />}
          loading={unenrollPending}
          onConfirm={() => unenroll({})}
          targetProps={{ c: "bw", w: 220 }}
          confirmProps={{ variant: "filled", color: "red" }}
        >
          Unenroll TOTP 2FA
        </ConfirmModal>
      )}
    </>
  );
};
