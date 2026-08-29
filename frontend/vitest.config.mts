import path from "path";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    // Installing @testing-library/jest-dom does not register its matchers.
    // Without this, toBeEmptyDOMElement() below is undefined at call time.
    setupFiles: ["./vitest.setup.ts"],
  },
  resolve: {
    alias: { "@": path.resolve(import.meta.dirname, "./") },
  },
});
