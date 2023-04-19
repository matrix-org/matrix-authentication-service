import { CodegenConfig } from "@graphql-codegen/cli";

const config: CodegenConfig = {
  schema: "./schema.graphql",
  documents: ["src/**/*.tsx", "!src/gql/**/*"],
  ignoreNoDocuments: true, // for better experience with the watcher
  generates: {
    "./src/gql/": {
      preset: "client",
      plugins: [],
    },
    "./src/gql/schema.ts": {
      plugins: ["urql-introspection"],
    },
  },
  hooks: { afterAllFileWrite: ["eslint --fix"] },
};

export default config;
