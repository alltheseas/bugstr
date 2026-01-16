import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  sourcemap: true,
  clean: true,
  dts: true,
  target: "es2019",
  treeshake: true,
  minify: false,
});
