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

import knex, { Knex } from "knex";

import {
  MASConfig,
  DatabaseConfig as MASDatabaseConfig,
  URIDatabaseConfig as MASURIDatabaseConfig,
} from "./schemas/mas.mjs";
import { SynapseConfig } from "./schemas/synapse.mjs";

export function connectToSynapseDatabase({
  database,
}: SynapseConfig): Knex<{}, unknown[]> {
  if (!database) {
    throw new Error("Synapse database not configured");
  }

  if (database.name === "sqlite3") {
    return knex({
      client: "sqlite3",
      connection: { filename: database.args.database },
      useNullAsDefault: true,
    });
  }

  const connection: Knex.PgConnectionConfig = {};
  database.args.database && (connection.database = database.args.database);
  database.args.user && (connection.user = database.args.user);
  database.args.password && (connection.password = database.args.password);
  typeof database.args.port === "number" &&
    (connection.port = database.args.port);
  typeof database.args.port === "string" &&
    (connection.port = parseInt(database.args.port));

  return knex({
    client: "pg",
    connection,
  });
}

const isUriConfig = (
  database: MASDatabaseConfig,
): database is MASURIDatabaseConfig =>
  typeof (database as Record<string, unknown>)["uri"] === "string";

export function connectToMASDatabase({
  database,
}: MASConfig): Knex<{}, unknown[]> {
  const connection: Knex.PgConnectionConfig = {};
  if (isUriConfig(database)) {
    connection.connectionString = database.uri;
  } else {
    database.database && (connection.database = database.database);
    database.username && (connection.user = database.username);
    database.password && (connection.password = database.password);
    database.port && (connection.port = database.port);
  }

  return knex({
    client: "pg",
    connection,
  });
}
