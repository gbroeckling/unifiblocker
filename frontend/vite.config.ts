import { defineConfig } from "vite";

// One ES module, written straight into the integration's www folder, which
// HA serves as the panel's module_url. The built file is committed so HACS
// installs don't need Node.
export default defineConfig({
  build: {
    lib: { entry: "src/panel.ts", formats: ["es"], fileName: () => "panel.js" },
    outDir: "../custom_components/unifiblocker/www/unifiblocker",
    emptyOutDir: false,
    target: "es2021",
    minify: true,
    sourcemap: false,
  },
});
