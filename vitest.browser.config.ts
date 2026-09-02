import { playwright } from "@vitest/browser-playwright";
import topLevelAwait from "vite-plugin-top-level-await";
import wasm from "vite-plugin-wasm";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [wasm(), topLevelAwait()],
  test: {
    include: ["test/**/*.browser.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**", "**/target/**"],
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: "chromium" }],
    },
  },
});
