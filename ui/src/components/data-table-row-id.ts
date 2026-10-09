/**
 * How `DataTable` keys its rows (and their cells): by `selectKey` when
 * rows can be selected (the selection's keys are the row ids), else by
 * `getRowId`, else by their index (TanStack's default, `undefined`
 * here).
 */
export function dataTableRowId<TData>(
  selectKey: ((row: TData) => string) | undefined,
  getRowId: ((row: TData, index: number) => string) | undefined,
): ((row: TData, index: number) => string) | undefined {
  return selectKey ? (row) => selectKey(row) : getRowId;
}
