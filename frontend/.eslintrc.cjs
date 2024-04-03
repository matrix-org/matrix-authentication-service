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

/** @type {import('eslint').Linter.Config} */

module.exports = {
  ignorePatterns: [
    "**/dist/**",
    "**/__generated__/**",
    "**/coverage/**",
    "!.storybook/locales.ts",
    "*/gql/*.ts",
  ],
  overrides: [
    // General rules for JS/TS files
    {
      extends: [
        "prettier",
        "plugin:import/recommended",
        "plugin:import/typescript",
        "plugin:matrix-org/typescript",
        "plugin:matrix-org/react",
        "plugin:matrix-org/a11y",
      ],
      env: {
        browser: true,
        node: true,
        es6: true,
      },
      plugins: ["jsx-a11y", "matrix-org"],
      parserOptions: {
        project: ["./tsconfig.node.json", "./tsconfig.json"],
        warnOnUnsupportedTypeScriptVersion: false,
      },
      files: ["*.ts", "*.tsx", "*.cjs", "*.js"],
      rules: {
        "matrix-org/require-copyright-header": "error",
        "import/order": [
          "error",
          {
            "newlines-between": "always",
            alphabetize: { order: "asc" },
          },
        ],
        // override enzyme deprecation from matrix-eslint
        // as it causes errors
        "deprecate/import": "off",
      },
      settings: {
        "import/resolver": {
          typescript: true,
        },
        react: {
          version: "detect",
        },
      },
    },

    // Processor to extract GraphQL operations embedded in TS files
    {
      files: ["*.tsx", "*.ts"],
      processor: "@graphql-eslint/graphql",
    },

    // Validate the GraphQL schema
    {
      files: "./schema.graphql",
      extends: [
        "plugin:@graphql-eslint/schema-recommended",
        "plugin:@graphql-eslint/relay",
        "prettier",
      ],
      rules: {
        "@graphql-eslint/input-name": [
          "error",
          { checkInputType: true, caseSensitiveInputType: false },
        ],
        "@graphql-eslint/relay-edge-types": [
          "error",
          {
            // We do have *some* fields without connections,
            // and async-graphql's connections 'nodes' field break this anyway
            listTypeCanWrapOnlyEdgeType: false,
          },
        ],

        "@graphql-eslint/strict-id-in-types": [
          "error",
          {
            exceptions: {
              // The '*Connection', '*Edge', '*Payload' and 'PageInfo' types don't have IDs
              // XXX: Maybe the MatrixUser type should have an ID?
              types: ["PageInfo", "MatrixUser", "UserAgent"],
              suffixes: ["Connection", "Edge", "Payload"],
            },
          },
        ],

        // We need to disable this rule because of the 'username' field in the 'User' node
        "@graphql-eslint/no-typename-prefix": "off",

        // We need to disable this rule for object types,
        // because the '*Connection' types lack descriptions
        "@graphql-eslint/require-description": [
          "error",
          {
            types: true,
            ObjectTypeDefinition: false,
          },
        ],
      },
    },

    // Validate the GraphQL operations
    {
      files: "./src/**/*.graphql",
      extends: ["plugin:@graphql-eslint/operations-recommended"],
      rules: {
        "@graphql-eslint/known-fragment-names": "off",
        "@graphql-eslint/no-unused-fragments": "off",
        "@graphql-eslint/unused-arguments": "off",
        "@graphql-eslint/known-directives": "off",
        // This rule is copied from the 'operations-recommended' config,
        // but without the 'Query' forbidden suffix on operations,
        // since it directly clashes with the relay operation naming convention
        "@graphql-eslint/naming-convention": [
          "error",
          {
            VariableDefinition: "camelCase",
            OperationDefinition: {
              style: "PascalCase",
              forbiddenPrefixes: ["Query", "Mutation", "Subscription", "Get"],
              forbiddenSuffixes: [/* "Query", */ "Mutation", "Subscription"],
            },
            FragmentDefinition: {
              forbiddenPrefixes: ["Fragment"],
              forbiddenSuffixes: ["Fragment"],
            },
          },
        ],
      },
    },
  ],
};
