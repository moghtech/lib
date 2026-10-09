import { Fragment, ReactNode, SetStateAction, useEffect, useMemo } from "react";
import { useDisclosure } from "@mantine/hooks";
import { MonacoLanguage } from "../monaco";
import {
  Anchor,
  Box,
  Button,
  Flex,
  Group,
  ScrollArea,
  Select,
  Stack,
  Text,
} from "@mantine/core";
import { ConfirmUpdateModal, SecretKey } from "./confirm";
import { confirmDialogOpen } from "./confirm-open";
import { Bookmark, History, Save } from "lucide-react";
import { ConfigGroup } from "./group";
import { UnsavedChanges } from "./unsaved-changes";
import { ConfigLayout } from "./layout";
import { SectionProps } from "../section";
import { useCtrlKeyListener } from "../../hooks";

export * from "./confirm";
export * from "./group";
export * from "./item";
export * from "./layout";
export * from "./number-input";
export * from "./unsaved-changes";

export interface ConfigFieldArgs {
  label?: string;
  description?: ReactNode;
  /** Useful to set explicitly in cases where value is nullable from the API (so type cannot be inferred). */
  type?:
    | "string"
    | "number"
    | "bigint"
    | "boolean"
    | "symbol"
    | "undefined"
    | "object"
    | "function";
  /** Use a selector instead of input */
  options?: { value: string; label?: string }[];
  placeholder?: string;
  hidden?: boolean;
  disabled?: boolean;
  /** Shown at the input, eg. why the value can't be saved. */
  error?: ReactNode;
  /**
   * A string holding a credential (eg. a webhook secret): a masked
   * input with a toggle to show it (`ConfigSecretInput`), and the
   * confirm dialog shows that it changed, never its values (as for
   * `secretKeys`).
   */
  secret?: boolean;
}

export interface ConfigGroupArgs<T> {
  label: string;
  labelExtra?: ReactNode;
  icon?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  hidden?: boolean;
  labelHidden?: boolean;
  contentHidden?: boolean;
  fields: {
    [K in keyof Partial<T>]:
      | boolean
      | ConfigFieldArgs
      | ((value: T[K], set: (value: Partial<T>) => void) => ReactNode);
  };
}

export interface ConfigProps<T> extends SectionProps {
  original: T;
  update: Partial<T>;
  setUpdate: React.Dispatch<SetStateAction<Partial<T>>>;
  disabled: boolean;
  onSave: () => Promise<unknown>;
  disableSidebar?: boolean;
  fileContentsLanguage?: MonacoLanguage;
  enableFancyToml?: boolean;
  /**
   * Fields holding secrets (a credential being set): the confirm
   * dialog shows that they change, never their values (see
   * `SecretKey`).
   */
  secretKeys?: SecretKey<T>[];
  groups: Record<
    string, // Section key
    ConfigGroupArgs<T>[] | false | undefined
  >;
}

export function Config<T>({
  original,
  update,
  setUpdate,
  disabled,
  onSave,
  disableSidebar,
  fileContentsLanguage,
  enableFancyToml,
  secretKeys,
  groups: _groups,
  ...sectionProps
}: ConfigProps<T>) {
  const changesMade = Object.keys(update).length ? true : false;
  const onConfirm = async () => {
    await onSave();
    setUpdate({});
  };
  const onReset = () => setUpdate({});

  // One confirm dialog (and one set of key listeners) per Config, however
  // many Save buttons the responsive layout below renders.
  const [confirmOpened, confirm] = useDisclosure();
  useCtrlKeyListener("Enter", (e) => {
    if (
      confirmOpened ||
      confirmDialogOpen() ||
      disabled ||
      !changesMade ||
      e.defaultPrevented
    ) {
      return false;
    }
    confirm.open();
  });
  // Changes dropped while the dialog is open (eg. by the parent).
  useEffect(() => {
    if (!changesMade) confirm.close();
  }, [changesMade]);

  const groups = useMemo(
    () => Object.entries(_groups).filter(([_, groupArgs]) => !!groupArgs),
    [_groups],
  );

  // The fields marked `secret`, never shown in the confirm dialog either.
  const allSecretKeys = useMemo(() => {
    const fieldKeys = groups.flatMap(([_, groupArgs]) =>
      (groupArgs as ConfigGroupArgs<T>[]).flatMap(({ fields }) =>
        Object.entries(fields)
          .filter(
            ([_, field]) =>
              typeof field === "object" && (field as ConfigFieldArgs).secret,
          )
          .map(([key]) => key as keyof T),
      ),
    );
    return [...(secretKeys ?? []), ...fieldKeys];
  }, [groups, secretKeys]);

  const GroupsComponent = useMemo(
    () =>
      groups.map(([group, groupArgs]) => {
        return (
          <Fragment key={group}>
            {group && (
              <Text visibleFrom="lg" fz="h2" tt="uppercase" mt="xl">
                {group}
              </Text>
            )}

            <Stack>
              {(groupArgs as ConfigGroupArgs<T>[])
                .filter(({ hidden }) => !hidden)
                .map(
                  ({
                    label,
                    labelHidden,
                    icon,
                    labelExtra,
                    actions,
                    description,
                    contentHidden,
                    fields,
                  }) => (
                    <Stack
                      key={group + label}
                      id={group + label}
                      p="xl"
                      gap="md"
                      className="bordered-light"
                      bdrs="md"
                      style={{ scrollMarginTop: 94 }}
                    >
                      {!labelHidden && (
                        <Group justify="space-between">
                          <Stack gap="0">
                            <Group>
                              {icon}
                              <Text fz="h3">{label}</Text>
                              {labelExtra}
                            </Group>
                            {description && (
                              <Text c="dimmed">{description}</Text>
                            )}
                          </Stack>
                          {actions}
                        </Group>
                      )}
                      {!contentHidden && (
                        <ConfigGroup
                          config={original}
                          update={update}
                          setUpdate={(u) => setUpdate((p) => ({ ...p, ...u }))}
                          fields={fields}
                          disabled={disabled}
                        />
                      )}
                    </Stack>
                  ),
                )}
            </Stack>
          </Fragment>
        );
      }),
    // Everything it reads: `groups` alone would freeze the inputs for
    // a caller passing a stable `groups` object.
    [groups, original, update, setUpdate, disabled],
  );

  const saveOrResetProps = {
    disabled,
    onReset,
    onSave: confirm.open,
  };

  const SaveOrResetComponent = changesMade && (
    <>
      <Group visibleFrom="xs" justify="flex-end">
        <SaveOrReset unsavedIndicator {...saveOrResetProps} />
      </Group>
      <Stack hiddenFrom="xs">
        <SaveOrReset unsavedIndicator fullWidth {...saveOrResetProps} />
      </Stack>
    </>
  );

  const ConfirmDialog = (
    <ConfirmUpdateModal
      opened={confirmOpened && changesMade}
      onClose={confirm.close}
      original={original}
      update={update}
      onConfirm={onConfirm}
      disabled={disabled}
      fileContentsLanguage={fileContentsLanguage}
      enableFancyToml={enableFancyToml}
      secretKeys={allSecretKeys}
    />
  );

  return (
    <ConfigLayout SaveOrReset={SaveOrResetComponent} {...sectionProps}>
      {ConfirmDialog}
      {disableSidebar && (
        <>
          {GroupsComponent}
          {SaveOrResetComponent}
        </>
      )}
      {!disableSidebar && (
        <Flex w="100%" gap="md" direction={{ base: "column", lg: "row" }}>
          {/** SIDEBAR (LG) */}
          <Box
            visibleFrom="lg"
            pos="relative"
            className="bordered-light"
            style={{
              borderLeftWidth: 0,
              borderBottomWidth: 0,
              borderTopRightRadius: "var(--mantine-radius-md)",
            }}
          >
            <Stack pos="sticky" w={175} top={88} pb={24} m="lg">
              {/** ANCHORS */}
              <ScrollArea
                mah={
                  changesMade ? "calc(100vh - 220px)" : "calc(100vh - 130px)"
                }
              >
                <Stack>
                  {groups
                    .filter(([_, groupArgs]) => groupArgs)
                    .map(([group, groupArgs]) => (
                      <Stack key={group} gap="xs">
                        <Group justify="flex-end" mr="md" c="dimmed">
                          <Bookmark size="1rem" />
                          <Text tt="uppercase">{group || "GENERAL"}</Text>
                        </Group>
                        <Stack gap="0.1rem">
                          {groupArgs &&
                            groupArgs
                              .filter((groupArgs) => !groupArgs.hidden)
                              .map((groupArgs) => (
                                <Button
                                  key={group + groupArgs.label}
                                  variant="subtle"
                                  justify="flex-end"
                                  size="sm"
                                  fullWidth
                                  renderRoot={(props) => (
                                    <Anchor
                                      href={"#" + group + groupArgs.label}
                                      {...props}
                                    />
                                  )}
                                >
                                  {groupArgs.label}
                                </Button>
                              ))}
                        </Stack>
                      </Stack>
                    ))}
                </Stack>
              </ScrollArea>

              {/** SAVE */}
              {changesMade && (
                <Stack gap="xs">
                  <SaveOrReset fullWidth {...saveOrResetProps} />
                </Stack>
              )}
            </Stack>
          </Box>

          {/** SELECTOR (MOBILE) */}
          <Select
            hiddenFrom="lg"
            className="select-nondimmed-placeholder"
            placeholder="Go To"
            leftSection={<Bookmark size="1rem" />}
            value={null}
            data={groups
              .filter(([_, groupArgs]) => groupArgs)
              .map(([group, groupArgs]) => ({
                group,
                items: (groupArgs as ConfigGroupArgs<T>[]).map((arg) => ({
                  label: arg.label,
                  value: group + arg.label,
                })),
              }))}
            onChange={(group) => {
              if (!group) return;
              window.location.hash = group;
            }}
          />

          {/** CONTENT */}
          <Stack style={{ flexGrow: 1 }} gap="md">
            {GroupsComponent}
            {SaveOrResetComponent}
          </Stack>
        </Flex>
      )}
    </ConfigLayout>
  );
}

/**
 * The Reset / Save buttons of a `Config`, shown at several responsive
 * positions (all stay mounted). Save only opens the Config's one
 * confirm dialog.
 */
function SaveOrReset({
  unsavedIndicator,
  fullWidth,
  disabled,
  onReset,
  onSave,
}: {
  unsavedIndicator?: boolean;
  fullWidth?: boolean;
  disabled: boolean;
  onReset: () => void;
  onSave: () => void;
}) {
  return (
    <>
      {unsavedIndicator && <UnsavedChanges fullWidth={fullWidth} />}
      <Button
        variant="outline"
        onClick={onReset}
        disabled={disabled}
        leftSection={<History size="1rem" />}
        fullWidth={fullWidth}
        w={fullWidth ? undefined : 100}
      >
        Reset
      </Button>
      <Button
        leftSection={<Save size="1rem" />}
        onClick={(e) => {
          e.stopPropagation();
          onSave();
        }}
        disabled={disabled}
        fullWidth={fullWidth}
        w={fullWidth ? undefined : 100}
      >
        Save
      </Button>
    </>
  );
}
