import { Button } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { Fingerprint, Trash } from "lucide-react";
import { ConfirmModal, useManageAuth } from "../..";
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

  const { mutate: confirmEnrollment } = useManageAuth(
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

  const { mutate: beginEnrollment } = useManageAuth("BeginPasskeyEnrollment", {
    onSuccess: (challenge) => {
      navigator.credentials
        .create(MoghAuth.Passkey.prepareCreationChallengeResponse(challenge))
        .then((credential) => confirmEnrollment({ credential }))
        .catch((e) => {
          console.error(e);
          notifications.show({
            title: "Failed to create passkey",
            message: "See console for details",
            color: "red",
          });
        });
    },
  });

  return (
    <>
      {!passkeyEnrolled && !totpEnrolled && (
        <Button
          leftSection={<Fingerprint size="1rem" />}
          onClick={() => beginEnrollment({})}
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
