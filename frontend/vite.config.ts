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

/// <reference types="vitest" />
import { defineConfig } from "vite";
import eslint from "vite-plugin-eslint";
import react from "@vitejs/plugin-react";
import relay from "vite-plugin-relay-lite";

export default defineConfig({
  base: "/app/",
  build: {
    manifest: true,
    assetsDir: "",
    sourcemap: true,
  },
  plugins: [
    react(),
    eslint({
      // Explicitly set the config file, else storybook gets confused
      overrideConfigFile: "./.eslintrc.cjs",
    }),
    relay(),
  ],
  server: {
    proxy: {
      // Routes mostly extracted from crates/router/src/endpoints.rs
      "^/(|graphql.*|assets.*|\\.well-known.*|oauth2.*|login.*|logout.*|register.*|reauth.*|account.*|consent.*|_matrix.*|complete-compat-sso.*)$":
        "http://127.0.0.1:8080",
    },
  },
  test: {
    coverage: {
      provider: "c8",
      src: ["./src/"],
      exclude: ["**/__generated__/**", "**/*.d.ts", "**/*.stories.*"],
      all: true,
    },
  },
});
