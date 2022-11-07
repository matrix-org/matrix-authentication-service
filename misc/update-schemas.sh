#!/bin/sh

set -eu

export SQLX_OFFLINE=1
BASE_DIR="$(dirname "$0")/.."
CONFIG_SCHEMA="${BASE_DIR}/docs/config.schema.json"
GRAPHQL_SCHEMA="${BASE_DIR}/crates/graphql/schema.graphql"

set -x
# XXX: we shouldn't have to specify this feature
cargo run -p mas-config --features webpki-roots > "${CONFIG_SCHEMA}"
cargo run -p mas-graphql --features webpki-roots > "${GRAPHQL_SCHEMA}"
