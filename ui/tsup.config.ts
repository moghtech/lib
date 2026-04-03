import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/**/*.{ts,tsx}", "!src/**/*.d.ts"],
  format: ["esm", "cjs"],
  bundle: false,
  dts: true,
  sourcemap: true,
  clean: true,
  external: ["react", "react-dom", "@mantine/core", "@mantine/hooks", /\.scss$/],
});
