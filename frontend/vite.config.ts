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

import { resolve } from "path";

import react from "@vitejs/plugin-react";
import compression from "vite-plugin-compression";
import codegen from "vite-plugin-graphql-codegen";
import manifestSRI from "vite-plugin-manifest-sri";
import svgr from "vite-plugin-svgr";
import { defineConfig } from "vitest/config";

export default defineConfig((env) => ({
  base: "./",
  build: {
    manifest: true,
    assetsDir: "",
    assetsInlineLimit: 0,
    sourcemap: true,
    modulePreload: false,

    rollupOptions: {
      input: [
        resolve(__dirname, "src/main.tsx"),
        resolve(__dirname, "src/templates.css"),
      ],
    },
  },
  plugins: [
    codegen(),

    react({
      babel: {
        plugins: [
          [
            "jotai/babel/plugin-react-refresh",
            {
              customAtomNames: [
                "mapQueryAtom",
                "atomWithPagination",
                "atomWithCurrentPagination",
              ],
            },
          ],
          [
            "jotai/babel/plugin-debug-label",
            {
              customAtomNames: [
                "mapQueryAtom",
                "atomWithPagination",
                "atomWithCurrentPagination",
              ],
            },
          ],
        ],
      },
    }),

    manifestSRI(),

    svgr({
      exportAsDefault: true,

      esbuildOptions: {
        // This makes sure we're using the same JSX runtime as React itself
        jsx: "automatic",
        jsxDev: env.mode === "development",
      },

      svgrOptions: {
        // Using 1em in order to make SVG size inherits from text size.
        icon: "1em",

        svgProps: {
          // Adding a class in case we want to add global overrides, but one
          // should probably stick to using CSS modules most of the time
          className: "cpd-icon",
        },
      },
    }),

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
  ],
  server: {
    base: "/account/",
    proxy: {
      // Routes mostly extracted from crates/router/src/endpoints.rs
      "^/(|graphql.*|assets.*|\\.well-known.*|oauth2.*|login.*|logout.*|register.*|reauth.*|add-email.*|verify-email.*|change-password.*|consent.*|_matrix.*|complete-compat-sso.*)$":
        "http://127.0.0.1:8080",
    },
  },
  test: {
    coverage: {
      provider: "v8",
      src: ["./src/"],
      exclude: ["**/gql/**", "**/*.d.ts", "**/*.stories.*"],
      all: true,
      reporter: ["text", "html", "lcov"],
    },
  },
}));
