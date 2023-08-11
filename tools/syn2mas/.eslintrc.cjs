module.exports = {
  plugins: [
    'matrix-org',
  ],
  extends: [
    'plugin:matrix-org/typescript',
  ],
  env: {
    browser: false,
    node: true,
  },
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: "./tsconfig.json",
  },
  rules: {
    '@typescript-eslint/no-floating-promises': 'error',
    '@typescript-eslint/no-misused-promises': 'error',
    '@typescript-eslint/promise-function-async': 'error',
    '@typescript-eslint/await-thenable': 'error',
  },
};
