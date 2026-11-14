// The internal modules of monaco-editor the node tests load (its types
// cover the public api only), as far as the tests use them.

declare module "monaco-editor/editor/common/standalone/standaloneEnums.js" {
  export const EditorOption: typeof import("monaco-editor").editor.EditorOption;
}

declare module "monaco-editor/platform/contextkey/common/contextkey.js" {
  /** A precondition, evaluated against an editor's context keys. */
  interface ContextKeyExpression {
    evaluate(context: { getValue(key: string): unknown }): boolean;
  }
  export const ContextKeyExpr: {
    deserialize(
      serialized: string | null | undefined,
    ): ContextKeyExpression | undefined;
  };
}

declare module "monaco-editor/editor/common/editorContextKeys.js" {
  export const EditorContextKeys: { readOnly: { key: string } };
}
