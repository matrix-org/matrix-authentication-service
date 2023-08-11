import knex, { Knex } from "knex";

import { SynapseConfig } from "./types/SynapseConfig";
import { MASConfig } from "./types/MASConfig";

export function connectToSynapseDatabase({ database }: SynapseConfig): Knex<{}, unknown[]> {
  if (database?.name === "sqlite3") {
    return knex({ client: "sqlite3", connection: { filename: database.args.database }, useNullAsDefault: true });
  }

  if (database.name === "psycopg2") {
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
