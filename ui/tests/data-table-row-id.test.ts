import { test } from "node:test";
import assert from "node:assert/strict";
import { dataTableRowId } from "../src/components/data-table-row-id.ts";

type Permission = { target: { type: string; id: string } };
const row: Permission = { target: { type: "Server", id: "abc" } };
const stable = (p: Permission) => `${p.target.type}:${p.target.id}`;

test("rows are keyed by a stable id when the table is given one", () => {
  // Komodo's permission tables (K7-13): a row's "Specific" selector
  // keeps a draft, which must not move to another resource's row when
  // a filter changes the rows at its index.
  assert.equal(dataTableRowId(undefined, stable)?.(row, 3), "Server:abc");
  // The selection's keys are the row ids: `selectKey` wins.
  assert.equal(
    dataTableRowId((p: Permission) => p.target.id, stable)?.(row, 3),
    "abc",
  );
  // Neither: TanStack's default, the index.
  assert.equal(dataTableRowId<Permission>(undefined, undefined), undefined);
});
