import knex, { Knex } from "knex";

import { DatabaseConfig, Psycopg2DatabaseConfig, Sqlite3DatabaseConfig, SynapseConfig } from "./types/SynapseConfig";
import { MASConfig } from "./types/MASConfig";

function isSqlite3(config: DatabaseConfig): config is Sqlite3DatabaseConfig {
    return config.name === "sqlite3";
}

function isPsycopg2(config: DatabaseConfig): config is Psycopg2DatabaseConfig {
  return config.name === "psycopg2";
}

export function connectToSynapseDatabase({ database }: SynapseConfig): Knex<{}, unknown[]> {
  if (!database) {
    throw new Error("Synapse database not configured");
  }

  if (isSqlite3(database)) {
    const filename = database.args?.database;
    if (!filename) {
        throw new Error("Synapse sqlite3 database not configured");
    }

    return knex({ client: "sqlite3", connection: { filename }, useNullAsDefault: true });
  }

  if (isPsycopg2(database)) {
    return knex({ client: "pg", connection: {
      user: database?.args?.user,
      database: database?.args?.database,
      password: database?.args?.password,
      port: database?.args?.port,
      host: database?.args?.host,
    } });
  }

  throw new Error(`Unsupported database type ${database?.name}. Must be sqlite3 or psycopg2`);
}

export function connectToMASDatabase({ database }: MASConfig): Knex<{}, unknown[]> {
  return knex({ client: "pg", connection: database?.uri });
}
