// Copyright 2023 The Matrix.org Foundation C.I.C.
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

import { CodegenConfig } from "@graphql-codegen/cli";

// Adds a comment to the top of generated files to ignore linting and formatting
const lintIgnore = {
  add: {
    content: "/* prettier-ignore */\n/* eslint-disable */",
  },
} as const;

const config: CodegenConfig = {
  schema: "./schema.graphql",
  documents: ["src/**/*.{tsx,ts}", "!src/gql/**/*"],
  ignoreNoDocuments: true, // for better experience with the watcher
  generates: {
    "./src/gql/": {
      preset: "client",
      config: {
        // By default, unknown scalars are generated as `any`. This is not ideal for catching potential bugs.
        defaultScalarType: "unknown",
        scalars: {
          DateTime: "string",
          Url: "string",
        },
      },
      plugins: [lintIgnore],
    },
    "./src/gql/schema.ts": {
      plugins: ["urql-introspection", lintIgnore],
    },
  },
};

export default config;
