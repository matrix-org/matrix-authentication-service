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

import { readFile } from "node:fs/promises";
import type { SecureContextOptions } from "node:tls";

import knex, { Knex } from "knex";

import {
  MASConfig,
  DatabaseConfig as MASDatabaseConfig,
  URIDatabaseConfig as MASURIDatabaseConfig,
} from "./schemas/mas.mjs";
import { SynapseConfig } from "./schemas/synapse.mjs";

export async function connectToSynapseDatabase({
  database,
}: SynapseConfig): Promise<Knex<{}, unknown[]>> {
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
  database.args.dbname && (connection.database = database.args.dbname);
  database.args.user && (connection.user = database.args.user);
  database.args.password && (connection.password = database.args.password);
  database.args.host && (connection.host = database.args.host);
  typeof database.args.port === "number" &&
    (connection.port = database.args.port);
  typeof database.args.port === "string" &&
    (connection.port = parseInt(database.args.port));

  const ssl: SecureContextOptions = {};
  database.args.sslcert && (ssl.cert = await readFile(database.args.sslcert));
  database.args.sslrootcert &&
    (ssl.ca = await readFile(database.args.sslrootcert));
  database.args.sslkey && (ssl.key = await readFile(database.args.sslkey));
  database.args.sslpassword && (ssl.passphrase = database.args.sslpassword);

  connection.ssl = ssl;

  return knex({
    client: "pg",
    connection,
  });
}

const isUriConfig = (
  database: MASDatabaseConfig,
): database is MASURIDatabaseConfig =>
  typeof (database as Record<string, unknown>)["uri"] === "string";

export async function connectToMASDatabase({
  database,
}: MASConfig): Promise<Knex<{}, unknown[]>> {
  const connection: Knex.PgConnectionConfig = {};
  const ssl: SecureContextOptions = {};
  if (isUriConfig(database)) {
    connection.connectionString = database.uri;
  } else {
    database.database && (connection.database = database.database);
    database.username && (connection.user = database.username);
    database.password && (connection.password = database.password);
    database.host && (connection.host = database.host);
    database.port && (connection.port = database.port);
  }

  if (database.ssl_ca) {
    ssl.ca = database.ssl_ca;
  } else if (database.ssl_ca_file) {
    ssl.ca = await readFile(database.ssl_ca_file);
  }

  if (database.ssl_certificate) {
    ssl.cert = database.ssl_certificate;
  } else if (database.ssl_certificate_file) {
    ssl.cert = await readFile(database.ssl_certificate_file);
  }

  if (database.ssl_key) {
    ssl.key = database.ssl_key;
  } else if (database.ssl_key_file) {
    ssl.key = await readFile(database.ssl_key_file);
  }

  connection.ssl = ssl;

  return knex({
    client: "pg",
    connection,
  });
}
