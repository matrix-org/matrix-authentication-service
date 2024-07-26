// Copyright 2022 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { readFile, writeFile } from "fs/promises";
import { resolve } from "path";

import { TanStackRouterVite as tanStackRouter } from "@tanstack/router-vite-plugin";
import react from "@vitejs/plugin-react";
import browserslistToEsbuild from "browserslist-to-esbuild";
import type { Manifest, PluginOption } from "vite";
import compression from "vite-plugin-compression";
import codegen from "vite-plugin-graphql-codegen";
import manifestSRI from "vite-plugin-manifest-sri";
import { defineConfig } from "vitest/config";

function i18nHotReload(): PluginOption {
  return {
    name: "i18n-hot-reload",
    handleHotUpdate({ file, server }): void {
      if (file.includes("locales") && file.endsWith(".json")) {
        console.log("Locale file updated");
        server.hot.send({
          type: "custom",
          event: "locales-update",
        });
      }
    },
  };
}

export default defineConfig((env) => ({
  base: "./",

  css: {
    modules: {
      localsConvention: "camelCaseOnly",
    },
  },

  define: {
    "import.meta.vitest": "undefined",
  },

  build: {
    manifest: "manifest.json",
    assetsDir: "",
    assetsInlineLimit: 0,
    sourcemap: true,
    modulePreload: false,
    target: browserslistToEsbuild(),
    cssCodeSplit: true,

    rollupOptions: {
      input: [
        resolve(__dirname, "src/main.tsx"),
        resolve(__dirname, "src/shared.css"),
        resolve(__dirname, "src/templates.css"),
        resolve(__dirname, "src/swagger.tsx"),
      ],
    },
  },

  plugins: [
    codegen(),

    react(),

    tanStackRouter(),

    // Custom plugin to make sure that each asset has an entry in the manifest
    // This is needed so that the preloading & asset integrity generation works
    {
      name: "manifest-missing-assets",

      apply: "build",
      enforce: "post",
      writeBundle: {
        // This needs to be executed sequentially before the manifestSRI plugin
        sequential: true,
        order: "pre",
        async handler({ dir }): Promise<void> {
          const manifestPath = resolve(dir, "manifest.json");

          const manifest: Manifest | undefined = await readFile(
            manifestPath,
            "utf-8",
          ).then(JSON.parse, () => undefined);

          if (manifest) {
            const existing: Set<string> = new Set();
            const needs: Set<string> = new Set();

            for (const chunk of Object.values(manifest)) {
              existing.add(chunk.file);
              for (const css of chunk.css ?? []) needs.add(css);
              for (const sub of chunk.assets ?? []) needs.add(sub);
            }

            const missing = Array.from(needs).filter((a) => !existing.has(a));

            if (missing.length > 0) {
              for (const asset of missing) {
                manifest[asset] = {
                  file: asset,
                  integrity: "",
                };
              }

              await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
            }
          }
        },
      },
    },

    manifestSRI(),

    // Pre-compress the assets, so that the server can serve them directly
    compression({
      algorithm: "gzip",
      ext: ".gz",
    }),
    compression({
      algorithm: "brotliCompress",
      ext: ".br",
    }),
    compression({
      algorithm: "deflate",
      ext: ".zz",
    }),

    i18nHotReload(),
  ],

  server: {
    base: "/account/",
    proxy: {
      // Routes mostly extracted from crates/router/src/endpoints.rs
      "^/(|graphql.*|assets.*|\\.well-known.*|oauth2.*|login.*|logout.*|register.*|reauth.*|add-email.*|verify-email.*|change-password.*|consent.*|_matrix.*|complete-compat-sso.*|link.*|device.*|upstream.*)$":
        "http://127.0.0.1:8080",
    },
  },

  test: {
    globalSetup: "./vitest.global-setup.ts",
    setupFiles: "./vitest.i18n-setup.ts",
    coverage: {
      provider: "v8",
      src: ["./src/"],
      exclude: ["**/gql/**", "**/*.d.ts", "**/*.stories.*"],
      all: true,
      reporter: ["text", "html", "lcov"],
    },
  },
}));
