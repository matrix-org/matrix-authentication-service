import knex, { Knex } from "knex";

import { SynapseConfig } from "./schemas/synapse.mjs";
import {
  MASConfig,
  DatabaseConfig as MASDatabaseConfig,
  URIDatabaseConfig as MASURIDatabaseConfig,
} from "./schemas/mas.mjs";

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

  return knex({
    client: "pg",
    connection: {
      user: database.args.user || undefined,
      database: database.args.database || undefined,
      password: database.args.password || undefined,
      port:
        typeof database.args.port === "string"
          ? parseInt(database.args.port)
          : database.args.port || undefined,
      host: database.args.host || undefined,
    },
  });
}

const isUriConfig = (
  database: MASDatabaseConfig,
): database is MASURIDatabaseConfig =>
  typeof (database as Record<string, unknown>).uri === "string";

export function connectToMASDatabase({
  database,
}: MASConfig): Knex<{}, unknown[]> {
  return knex({
    client: "pg",
    connection: isUriConfig(database)
      ? {
          connectionString: database.uri,
        }
      : {
          host: database.host,
          port: database.port,
          user: database.username,
          password: database.password,
          database: database.database,
        },
  });
}
