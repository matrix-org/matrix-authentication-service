import { z } from "zod";

const uriDatabaseConfig = z.object({
  uri: z.string(),
});

export type URIDatabaseConfig = z.infer<typeof uriDatabaseConfig>;

const objectDatabaseConfig = z.object({
  host: z.string().optional(),
  port: z.number().optional(),
  username: z.string().optional(),
  password: z.string().optional(),
  database: z.string().optional(),
});

const databaseConfig = z.union([uriDatabaseConfig, objectDatabaseConfig]);

export type DatabaseConfig = z.infer<typeof databaseConfig>;

const secretsConfig = z.object({
  encryption: z.string(),
});

export const masConfig = z.object({
  database: databaseConfig,
  secrets: secretsConfig,
});

export type MASConfig = z.infer<typeof masConfig>;
