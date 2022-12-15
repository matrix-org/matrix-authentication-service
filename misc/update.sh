#!/bin/sh

set -eu

export SQLX_OFFLINE=1
BASE_DIR="$(dirname "$0")/.."
CONFIG_SCHEMA="${BASE_DIR}/docs/config.schema.json"
GRAPHQL_SCHEMA="${BASE_DIR}/frontend/schema.graphql"

set -x
cargo run -p mas-config > "${CONFIG_SCHEMA}"
cargo run -p mas-graphql > "${GRAPHQL_SCHEMA}"

cd "${BASE_DIR}/frontend"
npm run generate
