import { exec } from "child_process";
import { readFileSync, writeFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

console.log("generating typescript types...");

const gen_command =
  "RUST_BACKTRACE=1 typeshare ./auth --lang=typescript --output-file=./auth/client/ts/src/types.ts";

exec(gen_command, (error, _stdout, _stderr) => {
  if (error) {
    console.error(error);
    return;
  }
  console.log("generated types using typeshare");
  fix_types();
  console.log("finished.");
});

function fix_types() {
  const types_path = __dirname + "/src/types.ts";
  const contents = readFileSync(types_path);
  const fixed = contents
    .toString()
    // Apply fixes
    .replaceAll("IndexSet", "Array")
    .replaceAll("IndexMap", "Record");
  writeFileSync(types_path, fixed);
}
