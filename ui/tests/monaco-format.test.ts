import { test } from "node:test";
import assert from "node:assert/strict";
import {
  formatDocumentAction,
  isFormatLanguage,
  type Format,
} from "../src/components/monaco/format-action.ts";

// Monaco's own pieces which load without a browser.
const { EditorOption } =
  await import("monaco-editor/editor/common/standalone/standaloneEnums.js");
const { ContextKeyExpr } =
  await import("monaco-editor/platform/contextkey/common/contextkey.js");
const { EditorContextKeys } =
  await import("monaco-editor/editor/common/editorContextKeys.js");

const READ_ONLY = EditorOption.readOnly;

/** An editor showing `value`, as much of one as the action uses. */
function fakeEditor(value: string, state: { readOnly: boolean }) {
  /** What the action did to the editor, in order. */
  const calls: string[] = [];
  const model = {
    version: 1,
    isDisposed: () => false,
    getOffsetAt: () => 0,
    getPositionAt: (offset: number) => ({ lineNumber: 1, column: offset + 1 }),
    getVersionId: () => model.version,
    getFullModelRange: () => ({ full: editor.value }),
  };
  const editor = {
    value,
    calls,
    model,
    /** Typing while the format runs. */
    type(text: string) {
      editor.value += text;
      model.version += 1;
    },
    getOption(option: number) {
      assert.equal(option, READ_ONLY);
      return state.readOnly;
    },
    getModel: () => model,
    getPosition: () => ({ lineNumber: 1, column: 1 }),
    getValue: () => editor.value,
    // Clears the undo history: the action mustn't use it.
    setValue() {
      assert.fail("setValue clears the undo history");
    },
    pushUndoStop() {
      calls.push("pushUndoStop");
      return true;
    },
    // Like monaco's, refuses a read only editor.
    executeEdits(
      source: string,
      edits: { range: { full: string }; text: string }[],
    ) {
      calls.push(`executeEdits ${source}`);
      if (state.readOnly) return false;
      assert.equal(edits.length, 1);
      assert.equal(edits[0].range.full, editor.value, "the whole text");
      editor.value = edits[0].text;
      model.version += 1;
      return true;
    },
    setPosition() {
      calls.push("setPosition");
    },
  };
  return editor;
}

function action(format: Format) {
  return formatDocumentAction({
    language: "yaml",
    keybindings: [1],
    readOnlyOption: READ_ONLY as never,
    format,
  });
}

const formatted: Format = async (_, source) => ({
  formatted: `${source.trim()}\n`,
  cursorOffset: 0,
});

test("the format action rewrites a writable editor", async () => {
  const editor = fakeEditor("a: 1   \n\n", { readOnly: false });
  await action(formatted).run(editor as never);
  assert.equal(editor.value, "a: 1\n");
});

test("a format is one edit, which undo reverts", async () => {
  const editor = fakeEditor("a: 1   \n\n", { readOnly: false });
  await action(formatted).run(editor as never);
  // An edit of the whole text between undo stops, which keeps the undo
  // history (`setValue` clears it).
  assert.deepEqual(editor.calls, [
    "pushUndoStop",
    "executeEdits mogh.format-document",
    "pushUndoStop",
    "setPosition",
  ]);
});

test("text typed while formatting is kept", async () => {
  const editor = fakeEditor("a: 1   \n", { readOnly: false });
  await action(async (...args) => {
    // Eg. while prettier loads, the editor stays editable
    editor.type("b: 2");
    return formatted(...args);
  }).run(editor as never);
  assert.equal(editor.value, "a: 1   \nb: 2");
  assert.deepEqual(editor.calls, []);
});

test("formatted text isn't edited again", async () => {
  const editor = fakeEditor("a: 1\n", { readOnly: false });
  await action(formatted).run(editor as never);
  assert.equal(editor.value, "a: 1\n");
  // No empty undo step
  assert.deepEqual(editor.calls, []);
});

test("the format action is off in a read only editor", async () => {
  const format = action(formatted);
  // Monaco checks the precondition (the keybinding's too) against the
  // editor's context keys, kept up to date when `readOnly` changes.
  const precondition = ContextKeyExpr.deserialize(format.precondition);
  assert.ok(precondition, "the precondition doesn't parse");
  const editorKeys = (readOnly: boolean) => ({
    getValue: (key: string) =>
      key === EditorContextKeys.readOnly.key ? readOnly : undefined,
  });
  assert.equal(precondition.evaluate(editorKeys(true)), false);
  assert.equal(precondition.evaluate(editorKeys(false)), true);
  assert.deepEqual(format.keybindings, [1]);

  // Run anyway (eg. `editor.trigger`): the text stays.
  let formats = 0;
  const editor = fakeEditor("a: 1   \n\n", { readOnly: true });
  await action(async (...args) => {
    formats++;
    return formatted(...args);
  }).run(editor as never);
  assert.equal(editor.value, "a: 1   \n\n");
  assert.equal(formats, 0);
});

test("a format finishing after the editor turned read only is dropped", async () => {
  const state = { readOnly: false };
  const editor = fakeEditor("a: 1   \n\n", state);
  await action(async (...args) => {
    // Eg. permissions loaded while prettier was loading
    state.readOnly = true;
    return formatted(...args);
  }).run(editor as never);
  assert.equal(editor.value, "a: 1   \n\n");
});

test("only yaml / typescript / javascript are formatted", () => {
  for (const language of ["yaml", "typescript", "javascript"]) {
    assert.equal(isFormatLanguage(language), true);
  }
  for (const language of ["toml", "json", "shell", undefined]) {
    assert.equal(isFormatLanguage(language), false);
  }
});
