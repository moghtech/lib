import { Button } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { Fingerprint, Trash } from "lucide-react";
import { useState } from "react";
import { ConfirmModal } from "../../components/confirm-modal";
import { useSingleFlight } from "../../hooks";
import { useManageAuth } from "../hooks";
import * as MoghAuth from "mogh_auth_client";

export function EnrollPasskey({
  userInvalidate,
  passkeyEnrolled,
  totpEnrolled,
}: {
  userInvalidate?: () => void;
  passkeyEnrolled?: boolean;
  totpEnrolled?: boolean;
}) {
  const { mutateAsync: unenroll, isPending: unenrollPending } = useManageAuth(
    "UnenrollPasskey",
    {
      onSuccess: () => {
        userInvalidate?.();
        notifications.show({
          message: "Unenrolled in passkey 2FA",
          color: "green",
        });
      },
    },
  );

  const { mutateAsync: confirmEnrollment } = useManageAuth(
    "ConfirmPasskeyEnrollment",
    {
      onSuccess: () => {
        userInvalidate?.();
        notifications.show({
          message: "Enrolled in passkey authentication",
          color: "green",
        });
      },
    },
  );

  const { mutateAsync: beginEnrollment } = useManageAuth(
    "BeginPasskeyEnrollment",
  );

  // One enrollment at a time, from the begin until its confirm settles:
  // the session keeps one, which a second begin replaces, so the
  // passkey the first prompt creates would be confirmed against the
  // second challenge and fail, left behind in the authenticator.
  // `enrolling` lags a render behind: a second click in the same tick.
  const [enrolling, setEnrolling] = useState(false);
  const enroll = useSingleFlight(async () => {
    setEnrolling(true);
    try {
      const challenge = await beginEnrollment({});
      let credential: Credential | null;
      try {
        credential = await navigator.credentials.create(
          MoghAuth.Passkey.prepareCreationChallengeResponse(challenge),
        );
      } catch (e) {
        console.error(e);
        notifications.show({
          title: "Failed to create passkey",
          message: "See console for details",
          color: "red",
        });
        return;
      }
      await confirmEnrollment({ credential });
    } catch {
      // The begin / confirm failure was notified (`useManageAuth`).
    } finally {
      setEnrolling(false);
    }
  });

  return (
    <>
      {!passkeyEnrolled && !totpEnrolled && (
        <Button
          leftSection={<Fingerprint size="1rem" />}
          onClick={() => enroll()}
          loading={enrolling}
          w={220}
        >
          Enroll Passkey 2FA
        </Button>
      )}
      {passkeyEnrolled && (
        <ConfirmModal
          confirmText="Unenroll"
          icon={<Trash size="1rem" />}
          loading={unenrollPending}
          onConfirm={() => unenroll({})}
          targetProps={{ c: "bw", w: 220 }}
          confirmProps={{ variant: "filled", color: "red" }}
        >
          Unenroll Passkey 2FA
        </ConfirmModal>
      )}
    </>
  );
}
