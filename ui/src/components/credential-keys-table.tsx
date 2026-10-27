import {
  ActionIcon,
  Button,
  Group,
  List,
  Popover,
  Stack,
  Text,
  TextInput,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import type {
  ColumnDef,
  RowData,
  RowSelectionState,
  SortingState,
} from "@tanstack/react-table";
import { Pencil, Save, Trash2 } from "lucide-react";
import {
  type Dispatch,
  type ReactNode,
  type SetStateAction,
  useMemo,
  useState,
} from "react";
import {
  CREDENTIAL_KEY_SORT_BY,
  type CredentialKey,
  type CredentialKeySortBy,
  type CredentialKeyUpdate,
  type Timestamp,
  credentialNameError,
  expiryMs,
  timestampMs,
} from "../credential-key";
import { CidrWhitelistCell } from "./cidr-whitelist-input";
import { ConfirmModal } from "./confirm-modal";
import { DataTable, DataTableFeatures, SortableHeader } from "./data-table";
import { EnableSwitch } from "./enable-switch";
import { ExpiresIn } from "./expires-in";
import { SearchInput } from "./search-input";

/** A column of the table over rows of `T`. */
export type CredentialKeyColumn<T extends RowData> = ColumnDef<
  DataTableFeatures,
  T,
  unknown
>;

export interface CredentialKeysTableProps<T extends CredentialKey> {
  /** The singular entity type, eg. "Api Key". */
  entity: string;
  tableKey: string;
  noBorder?: boolean;
  data: T[] | undefined;
  loading?: boolean;
  /** The kind's own column: the api key, or the public key. */
  keyColumn: CredentialKeyColumn<T>;
  /** The sortable columns' ids. Default: [CREDENTIAL_KEY_SORT_BY],
   * the rows sorted by the table itself. An app sorting server side
   * passes its request's sort keys, and `tableSortProps`
   * (`manualSorting`, `onSortingStateChange`) to be told the sort. */
  sortBy?: CredentialKeySortBy;
  tableSortProps?: {
    manualSorting?: boolean;
    onSortingStateChange?: (sorting: SortingState) => void;
  };
  /** The row selection, when the app keeps it (eg. to reset it with
   * the listing). Default: the table's own. */
  selection?: [RowSelectionState, Dispatch<SetStateAction<RowSelectionState>>];
  /** The search, when the app searches server side. Default: the
   * table filters its rows by name. */
  search?: { value: string; onSearch: (search: string) => void };
  /** More controls next to the search (eg. pagination). */
  toolbar?: ReactNode;
  /** The name rule of a rename. Default: [credentialNameError]. */
  nameError?: (name: string) => string | null;
  /** The line naming a key in the delete confirm. Default: its
   * name, or its id when it has none. */
  label?: (key: T) => ReactNode;
  /** Rejects when the update fails (the write's notification says
   * why): the editor stays open to fix it. */
  update: (update: CredentialKeyUpdate) => Promise<unknown>;
  /** Deletes the selected keys. */
  onDelete: (ids: string[]) => Promise<unknown>;
  /** The create button. */
  create?: ReactNode;
}

/**
 * The profile page's list of a user's api keys or signing keys: the
 * name (renamed inline), the kind's own key column (`keyColumn`),
 * the enabled switch, the expiry, the source ips (edited inline) and
 * the timestamps, with create (`create`), a search, row selection and
 * a confirmed delete of the selection.
 */
export function CredentialKeysTable<T extends CredentialKey>({
  entity,
  tableKey,
  noBorder,
  data,
  loading,
  keyColumn,
  sortBy = CREDENTIAL_KEY_SORT_BY,
  tableSortProps,
  selection,
  search,
  toolbar,
  nameError = credentialNameError,
  label,
  update,
  onDelete,
  create,
}: CredentialKeysTableProps<T>) {
  const ownSelection = useState<RowSelectionState>({});
  const [selected, setSelected] = selection ?? ownSelection;
  const [ownSearch, setOwnSearch] = useState("");

  const rows = useMemo(() => {
    if (!data) return [];
    if (search) return data;
    const needle = ownSearch.trim().toLowerCase();
    return needle
      ? data.filter((key) => key.name.toLowerCase().includes(needle))
      : data;
  }, [data, search, ownSearch]);

  // Only the rows of the listing: a selected id the listing no longer
  // holds is neither named in the confirm nor deleted.
  const selectedKeys = useMemo(
    () => rows.filter((key) => selected[key.id]),
    [rows, selected],
  );

  const columns = useMemo<CredentialKeyColumn<T>[]>(
    () => [
      {
        header: ({ column }) => <SortableHeader column={column} title="Name" />,
        id: sortBy.Name,
        accessorKey: "name",
        cell: ({ row }) => (
          <NameCell
            name={row.original.name}
            nameError={nameError}
            onRename={(name) => update({ id: row.original.id, name })}
          />
        ),
      },
      keyColumn,
      {
        header: ({ column }) => (
          <SortableHeader column={column} title="Enabled" sortDescFirst />
        ),
        id: sortBy.Enabled,
        accessorKey: "enabled",
        sortDescFirst: true,
        cell: ({ row }) => (
          <EnableSwitch
            checked={row.original.enabled}
            onCheckedChange={(enabled) =>
              // Notified by the write; the switch shows the record.
              update({ id: row.original.id, enabled }).catch(() => {})
            }
            redDisabled={false}
          />
        ),
      },
      {
        header: ({ column }) => (
          <SortableHeader column={column} title="Expires In" />
        ),
        id: sortBy.ExpiresAt,
        // Soonest first, never-expiring keys last.
        accessorFn: (key) =>
          expiryMs(key.expires_at) ?? Number.MAX_SAFE_INTEGER,
        cell: ({ row }) => <ExpiresIn expires={row.original.expires_at} />,
      },
      {
        header: "Source IPs",
        id: "cidr_whitelist",
        enableSorting: false,
        cell: ({ row }) => (
          <CidrWhitelistCell
            value={row.original.cidr_whitelist ?? []}
            onSave={(cidr_whitelist) =>
              update({ id: row.original.id, cidr_whitelist })
            }
          />
        ),
      },
      timestampColumn<T>(
        "Created At",
        sortBy.CreatedAt,
        (key) => key.created_at,
      ),
      timestampColumn<T>(
        "Updated At",
        sortBy.UpdatedAt,
        (key) => key.updated_at,
      ),
    ],
    [keyColumn, nameError, sortBy, update],
  );

  return (
    <Stack>
      <Group>
        {create}
        <DeleteSelected
          entity={entity}
          keys={selectedKeys}
          label={label}
          onDelete={async (ids) => {
            await onDelete(ids);
            setSelected({});
          }}
        />
        <SearchInput
          value={search ? search.value : ownSearch}
          onSearch={search ? search.onSearch : setOwnSearch}
        />
        {toolbar}
      </Group>
      <DataTable
        noBorder={noBorder}
        tableKey={tableKey}
        data={rows}
        loading={loading}
        {...tableSortProps}
        // Rows keyed by id, so a cell with a draft (a rename, a
        // whitelist) stays with its key when the rows reorder.
        selectOptions={{
          selectKey: (key) => key.id,
          state: [selected, setSelected],
        }}
        columns={columns}
      />
    </Stack>
  );
}

/** A `Created At` / `Updated At` column, newest first. A missing
 * timestamp (a record from before it was kept) shows as none, and
 * sorts last. */
function timestampColumn<T extends CredentialKey>(
  title: string,
  id: string,
  value: (key: T) => Timestamp | null | undefined,
): CredentialKeyColumn<T> {
  return {
    header: ({ column }) => (
      <SortableHeader column={column} title={title} sortDescFirst />
    ),
    id,
    sortDescFirst: true,
    accessorFn: (key) => timestampMs(value(key)) ?? 0,
    cell: ({ row }) => {
      const ms = timestampMs(value(row.original));
      return ms === null ? (
        <Text c="dimmed" fz="sm">
          —
        </Text>
      ) : (
        new Date(ms).toLocaleString()
      );
    },
  };
}

/** The confirmed delete of the selected keys, listing them by name.
 * Disabled while nothing is selected. */
function DeleteSelected<T extends CredentialKey>({
  entity,
  keys,
  label = (key) => key.name || key.id,
  onDelete,
}: {
  entity: string;
  keys: T[];
  label?: (key: T) => ReactNode;
  onDelete: (ids: string[]) => Promise<unknown>;
}) {
  const count = keys.length;
  const what = count === 1 ? entity : `${entity}s`;
  return (
    <ConfirmModal
      icon={<Trash2 size="1rem" />}
      disabled={!count}
      title={count ? `Delete ${count} ${what}` : `Delete ${what}`}
      additional={
        <Stack gap="xs">
          <Text fw="bold">To delete:</Text>
          <List>
            {keys.map((key) => (
              <List.Item key={key.id}>{label(key)}</List.Item>
            ))}
          </List>
          <Text fz="sm" c="dimmed">
            Requests made with {count === 1 ? "this key" : "these keys"} stop
            authenticating at once. This cannot be undone.
          </Text>
        </Stack>
      }
      onConfirm={() => onDelete(keys.map((key) => key.id))}
      confirmProps={{ color: "red" }}
      targetProps={{ variant: "light", color: "red", w: "fit-content" }}
    >
      {count ? `Delete (${count})` : "Delete"}
    </ConfirmModal>
  );
}

/** A key's name in its table cell, renamed in an inline popover.
 * The rename follows `nameError` (the create form's rule); a failed
 * one keeps the popover open to fix the name. */
function NameCell({
  name,
  nameError,
  onRename,
}: {
  name: string;
  nameError: (name: string) => string | null;
  onRename: (name: string) => Promise<unknown>;
}) {
  const [opened, { open, close }] = useDisclosure(false);
  const [draft, setDraft] = useState(name);
  const [pending, setPending] = useState(false);
  const error = nameError(draft);
  const submit = async () => {
    if (error || pending) return;
    if (draft === name) return close();
    setPending(true);
    try {
      await onRename(draft);
      close();
    } catch {
      // Notified by the write. Keep the input open to fix the name.
    } finally {
      setPending(false);
    }
  };
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
          color="gray"
          c={name ? "var(--mantine-color-text)" : "dimmed"}
          rightSection={<Pencil size="0.8rem" />}
          onClick={() => {
            setDraft(name);
            open();
          }}
        >
          {name || "No name"}
        </Button>
      </Popover.Target>
      <Popover.Dropdown onClick={(e) => e.stopPropagation()}>
        <Group gap="xs" wrap="nowrap" align="flex-start">
          <TextInput
            aria-label="Name"
            placeholder="Enter name"
            value={draft}
            onChange={(e) => setDraft(e.currentTarget.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()}
            error={error}
            disabled={pending}
            autoFocus
            flex={1}
          />
          <ActionIcon
            title="Save name"
            variant="filled"
            size="lg"
            onClick={submit}
            loading={pending}
            disabled={!!error}
          >
            <Save size="1rem" />
          </ActionIcon>
        </Group>
      </Popover.Dropdown>
    </Popover>
  );
}
