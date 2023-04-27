import { CodegenConfig } from "@graphql-codegen/cli";

const config: CodegenConfig = {
  schema: "./schema.graphql",
  documents: ["src/**/*.{tsx,ts}", "!src/gql/**/*"],
  ignoreNoDocuments: true, // for better experience with the watcher
  generates: {
    "./src/gql/": {
      preset: "client",
      plugins: [
        {
          add: {
            content: "/* eslint-disable */",
          },
        },
      ],
    },
    "./src/gql/schema.ts": {
      plugins: [
        {
          add: {
            content: "/* eslint-disable */",
          },
        },
        "urql-introspection",
      ],
    },
  },
  hooks: {
    afterOneFileWrite: ["prettier --write"],
  },
};

export default config;
