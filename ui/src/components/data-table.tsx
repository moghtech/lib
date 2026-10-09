import {
  ComponentPropsWithoutRef,
  Dispatch,
  MouseEvent,
  ReactNode,
  SetStateAction,
  useEffect,
  useLayoutEffect,
  useState,
} from "react";
import {
  Column,
  ColumnDef,
  columnVisibilityFeature,
  createSortedRowModel,
  flexRender,
  Row,
  RowData,
  RowSelectionState,
  rowSelectionFeature,
  rowSortingFeature,
  SortingState,
  sortFn_alphanumeric,
  sortFn_alphanumericCaseSensitive,
  sortFn_basic,
  sortFn_datetime,
  sortFn_text,
  sortFn_textCaseSensitive,
  tableFeatures,
  useTable,
} from "@tanstack/react-table";
import {
  Box,
  BoxProps,
  Center,
  Checkbox,
  DefaultMantineColor,
  Group,
  HoverCard,
  Loader,
  Table,
  TableProps,
  Text,
  UnstyledButton,
} from "@mantine/core";
import { ArrowDown, ArrowUp, Info, Minus } from "lucide-react";
import { dataTableRowId } from "./data-table-row-id";

// All built-in sort fns are registered so consumer columns can keep
// using `sortFn: "auto"` (the default) or any built-in name.
const features = tableFeatures({
  rowSortingFeature,
  rowSelectionFeature,
  columnVisibilityFeature,
  sortedRowModel: createSortedRowModel(),
  sortFns: {
    alphanumeric: sortFn_alphanumeric,
    alphanumericCaseSensitive: sortFn_alphanumericCaseSensitive,
    basic: sortFn_basic,
    datetime: sortFn_datetime,
    text: sortFn_text,
    textCaseSensitive: sortFn_textCaseSensitive,
  },
});

/** The table features `DataTable` is built with.
 * Use as the `TFeatures` generic on `ColumnDef` / `Column` etc. */
export type DataTableFeatures = typeof features;

function loadStoredSorting(tableKey: string): SortingState | null {
  try {
    const stored = localStorage.getItem("data-table-" + tableKey);
    if (!stored) return null;
    const parsed: unknown = JSON.parse(stored);
    // Anything else (eg. written by another version) is ignored.
    const valid =
      Array.isArray(parsed) &&
      parsed.every(
        (sort) =>
          typeof sort?.id === "string" && typeof sort?.desc === "boolean",
      );
    return valid ? (parsed as SortingState) : null;
  } catch {
    return null;
  }
}

function storeSorting(tableKey: string, sorting: SortingState) {
  try {
    localStorage.setItem("data-table-" + tableKey, JSON.stringify(sorting));
  } catch {
    // Storage blocked or full: the sorting just isn't remembered.
  }
}

export interface DataTableProps<
  TData extends RowData,
  TValue = unknown,
> extends BoxProps {
  /** Unique key given to table so sorting can be remembered on local storage */
  tableKey: string;
  columns: (ColumnDef<DataTableFeatures, TData, TValue> | false | undefined)[];
  data: TData[];
  /**
   * A stable id of a row, eg. its resource's id. React keys the rows
   * and their cells by it, so a cell with state of its own (an input
   * with a draft, a selector) stays with its row when the rows are
   * filtered, sorted or reordered. Default: the row's index, which
   * hands such a cell to whatever row moves into its place. With
   * `selectOptions` the rows are keyed by its `selectKey`.
   */
  getRowId?: (row: TData, index: number) => string;
  loading?: boolean;
  onRowClick?: (row: TData) => void;
  /** Called when a row is right clicked. The consumer decides whether to
   * `preventDefault` the native context menu. */
  onRowContextMenu?: (row: TData, e: MouseEvent<HTMLTableRowElement>) => void;
  /** Extra props (eg. drag and drop handlers) spread onto each data row's
   * `<tr>`. A returned `style` is merged over the row's base style. */
  rowProps?: (row: TData) => ComponentPropsWithoutRef<"tr">;
  noResults?: ReactNode;
  defaultSort?: SortingState;
  sortDescFirst?: boolean;
  /** Sorting is handled externally (eg. server side).
   * The table still manages / persists the sorting state,
   * but does not apply it to the rows. */
  manualSorting?: boolean;
  /** Called with the sorting state whenever it changes.
   * Also called on mount with the initial state
   * (loaded from local storage when available). */
  onSortingStateChange?: (sorting: SortingState) => void;
  selectOptions?: {
    selectKey: (row: TData) => string;
    onSelect?: (selected: string[]) => void;
    state?: [RowSelectionState, Dispatch<SetStateAction<RowSelectionState>>];
    /**
     * Which rows can be selected: `false` for none, or a predicate
     * returning `true` for the selectable rows. Default: all rows.
     */
    canSelectRow?: boolean | ((row: Row<DataTableFeatures, TData>) => boolean);
    color?: DefaultMantineColor;
  };
  caption?: string;
  tableProps?: TableProps;
  noBox?: boolean;
  noBorder?: boolean;
}

export function DataTable<TData extends RowData, TValue>({
  tableKey,
  columns,
  data,
  getRowId,
  loading,
  onRowClick,
  onRowContextMenu,
  rowProps,
  noResults = <Text c="dimmed">No results</Text>,
  sortDescFirst = false,
  defaultSort = [],
  manualSorting,
  onSortingStateChange,
  selectOptions,
  caption,
  tableProps,
  noBox,
  noBorder,
  mah = "max(150px, calc(100vh - 320px))",
  ...boxProps
}: DataTableProps<TData, TValue>) {
  // Initialized synchronously from local storage so the first render
  // (and any server side sorted query) already uses the persisted sort,
  // instead of flashing through the unsorted state.
  const [sorting, setSorting] = useState<SortingState>(
    () => loadStoredSorting(tableKey) ?? defaultSort,
  );
  const [prevTableKey, setPrevTableKey] = useState(tableKey);
  if (prevTableKey !== tableKey) {
    setPrevTableKey(tableKey);
    setSorting(loadStoredSorting(tableKey) ?? defaultSort);
  }

  // intentionally not initialized to clear selected values on table mount
  // could add some prop for adding default selected state to preserve between mounts
  const _internalState = useState<RowSelectionState>({});
  const [rowSelection, setRowSelection] = selectOptions?.state
    ? selectOptions.state
    : _internalState;

  const canSelectRow = selectOptions?.canSelectRow;

  const table = useTable({
    features,
    data,
    columns: columns.filter((c) => c) as any,
    onSortingChange: setSorting,
    manualSorting,
    state: {
      sorting,
      rowSelection,
    },
    sortDescFirst,
    onRowSelectionChange: setRowSelection,
    getRowId: dataTableRowId(selectOptions?.selectKey, getRowId),
    enableRowSelection: canSelectRow,
  });

  useEffect(() => {
    storeSorting(tableKey, sorting);
  }, [tableKey, sorting]);

  // Layout effect so the parent receives the initial (persisted) sorting
  // before any of its own passive effects run, ie before react-query
  // subscribes a server side sorted query using the pre-sort key.
  useLayoutEffect(() => {
    onSortingStateChange?.(sorting);
  }, [sorting]);

  useEffect(() => {
    selectOptions?.onSelect?.(Object.keys(rowSelection));
  }, [rowSelection]);

  const rows = table.getRowModel().rows;

  const tableNode = (
    <Table
      borderColor="accent-border"
      captionSide="top"
      stickyHeader
      {...tableProps}
    >
      {caption ? <Table.Caption>{caption}</Table.Caption> : null}

      <Table.Thead>
        {table.getHeaderGroups().map((hg, i) => (
          <Table.Tr key={hg.id}>
            {i === 0 && selectOptions && (
              <Table.Th
                onClick={() =>
                  canSelectRow !== false && table.toggleAllRowsSelected()
                }
                style={{
                  cursor: "pointer",
                  borderColor: "var(--mantine-color-accent-border-0)",
                  borderWidth: 0,
                  borderRightWidth: 1,
                  borderStyle: "solid",
                }}
              >
                <Checkbox
                  aria-label="Select all rows"
                  color={selectOptions.color ?? "Neutral"}
                  disabled={canSelectRow === false}
                  checked={table.getIsAllRowsSelected()}
                  indeterminate={
                    // v9: getIsSomeRowsSelected is true even when all are selected
                    table.getIsSomeRowsSelected() &&
                    !table.getIsAllRowsSelected()
                  }
                />
              </Table.Th>
            )}
            {hg.headers.map((header, i) => {
              // const canSort = header.column.getCanSort();
              // const sortState = header.column.getIsSorted();
              return (
                <Table.Th
                  key={header.id}
                  px="md"
                  style={{
                    cursor: "pointer",
                    borderColor: "var(--mantine-color-accent-border-0)",
                    borderWidth: 0,
                    borderRightWidth: i < hg.headers.length - 1 ? 1 : 0,
                    borderStyle: "solid",
                  }}
                >
                  {header.isPlaceholder ? null : (
                    <Text fw={600} size="sm" lineClamp={1}>
                      {flexRender(
                        header.column.columnDef.header,
                        header.getContext(),
                      )}
                    </Text>
                  )}
                </Table.Th>
              );
            })}
          </Table.Tr>
        ))}
      </Table.Thead>

      <Table.Tbody>
        {loading ? (
          <Table.Tr>
            <Table.Td
              colSpan={
                table.getAllLeafColumns().length + (selectOptions ? 1 : 0)
              }
            >
              <Group justify="center" py="lg">
                <Loader size="sm" />
              </Group>
            </Table.Td>
          </Table.Tr>
        ) : rows.length === 0 ? (
          <Table.Tr>
            <Table.Td
              colSpan={
                table.getAllLeafColumns().length + (selectOptions ? 1 : 0)
              }
            >
              <Group justify="center" py="lg">
                {noResults}
              </Group>
            </Table.Td>
          </Table.Tr>
        ) : (
          rows.map((row) => {
            const extraRowProps = rowProps?.(row.original);
            return (
              <Table.Tr
                key={row.id}
                onContextMenu={
                  onRowContextMenu
                    ? (e) => onRowContextMenu(row.original, e)
                    : undefined
                }
                // A row which opens something opens by keyboard too:
                // focusable, Enter / Space on the row itself (not on a
                // link or button inside it, which do their own thing).
                tabIndex={onRowClick ? 0 : undefined}
                onKeyDown={
                  onRowClick
                    ? (e) => {
                        if (
                          e.target === e.currentTarget &&
                          (e.key === "Enter" || e.key === " ")
                        ) {
                          e.preventDefault();
                          onRowClick(row.original);
                        }
                      }
                    : undefined
                }
                {...extraRowProps}
                style={{
                  cursor: onRowClick ? "pointer" : undefined,
                  contentVisibility: "auto",
                  containIntrinsicSize: "auto 2em",
                  ...extraRowProps?.style,
                }}
              >
                {selectOptions && (
                  <Table.Td onClick={() => row.toggleSelected()}>
                    <Checkbox
                      aria-label="Select row"
                      color={selectOptions.color ?? "Neutral"}
                      disabled={!row.getCanSelect()}
                      checked={row.getIsSelected()}
                    />
                  </Table.Td>
                )}
                {row.getVisibleCells().map((cell) => (
                  <Table.Td
                    key={cell.id}
                    onClick={
                      onRowClick ? () => onRowClick(row.original) : undefined
                    }
                    style={{ flexWrap: "nowrap", textWrap: "nowrap" }}
                  >
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </Table.Td>
                ))}
              </Table.Tr>
            );
          })
        )}
      </Table.Tbody>
    </Table>
  );

  if (noBox) {
    return tableNode;
  } else {
    return (
      <Box
        p={noBorder ? undefined : "lg"}
        pt="0"
        className={noBorder ? undefined : "bordered-light"}
        bdrs="md"
        w="100%"
        mah={mah}
        style={{ overflow: "auto" }}
        {...boxProps}
      >
        {tableNode}
      </Box>
    );
  }
}

export const SortableHeader = <T extends RowData, V>({
  column,
  title,
  description,
  sortDescFirst,
  disabled,
}: {
  column: Column<DataTableFeatures, T, V>;
  title: string;
  description?: ReactNode;
  sortDescFirst?: boolean;
  disabled?: boolean;
}) => {
  if (disabled || !column.getCanSort()) {
    return (
      <Group justify="start" gap="xs" wrap="nowrap" miw="120" w="fit-content">
        <Text fw={600} size="sm" lineClamp={1}>
          {title}
        </Text>
        {description && (
          <HoverCard offset={10}>
            <HoverCard.Target>
              <Info size="1rem" />
            </HoverCard.Target>
            <HoverCard.Dropdown>
              <Text>{description}</Text>
            </HoverCard.Dropdown>
          </HoverCard>
        )}
      </Group>
    );
  }
  return (
    <UnstyledButton
      onClick={column.getToggleSortingHandler()}
      style={{ width: "100%" }}
    >
      <Group justify="space-between" gap="sm" wrap="nowrap">
        <Group justify="start" gap="xs" wrap="nowrap" miw="120" w="fit-content">
          <Text fw={600} size="sm" lineClamp={1}>
            {title}
          </Text>
          {description && (
            <HoverCard offset={10}>
              <HoverCard.Target>
                <Info size="1rem" />
              </HoverCard.Target>
              <HoverCard.Dropdown>
                <Text>{description}</Text>
              </HoverCard.Dropdown>
            </HoverCard>
          )}
        </Group>
        <Center>
          <SortIcon
            state={column.getIsSorted()}
            sortDescFirst={sortDescFirst}
          />
        </Center>
      </Group>
    </UnstyledButton>
  );
};

function SortIcon({
  state,
  sortDescFirst,
}: {
  state: false | "asc" | "desc";
  sortDescFirst?: boolean;
}) {
  if (state === "asc")
    return sortDescFirst ? <ArrowUp size={14} /> : <ArrowDown size={14} />;
  if (state === "desc")
    return sortDescFirst ? <ArrowDown size={14} /> : <ArrowUp size={14} />;
  return <Minus size={14} />;
}
