#!/bin/sh

set -eu

export SQLX_OFFLINE=1
BASE_DIR="$(dirname "$0")/.."
CONFIG_SCHEMA="${BASE_DIR}/docs/config.schema.json"
API_SCHEMA="${BASE_DIR}/docs/api.schema.json"
GRAPHQL_SCHEMA="${BASE_DIR}/frontend/schema.graphql"
POLICIES_SCHEMA="${BASE_DIR}/policies/schema/"

set -x
cargo run -p mas-config > "${CONFIG_SCHEMA}"
cargo run -p mas-handlers --bin graphql-schema > "${GRAPHQL_SCHEMA}"
cargo run -p mas-handlers --bin api-schema > "${API_SCHEMA}"
cargo run -p mas-i18n-scan -- --update "${BASE_DIR}/templates/" "${BASE_DIR}/translations/en.json"
OUT_DIR="${POLICIES_SCHEMA}" cargo run -p mas-policy --features jsonschema

cd "${BASE_DIR}/frontend"
npm run format
npm run generate
