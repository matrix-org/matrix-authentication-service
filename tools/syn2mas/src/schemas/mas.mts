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

import * as z from "zod";

const ssl = z
  .object({
    ssl_ca: z.string().optional(),
    ssl_ca_file: z.string().optional(),
    ssl_certificate: z.string().optional(),
    ssl_certificate_file: z.string().optional(),
    ssl_key: z.string().optional(),
    ssl_key_file: z.string().optional(),
  })
  .refine((ssl) => {
    if (ssl.ssl_ca && ssl.ssl_ca_file) {
      throw new Error("Cannot specify both ssl_ca and ssl_ca_file");
    }

    if (ssl.ssl_certificate && ssl.ssl_certificate_file) {
      throw new Error("Cannot specify both ssl_cert and ssl_cert_file");
    }

    if (ssl.ssl_key && ssl.ssl_key_file) {
      throw new Error("Cannot specify both ssl_key and ssl_key_file");
    }

    return true;
  });

const uriDatabaseConfig = z
  .object({
    uri: z.string(),
  })
  .and(ssl);

export type URIDatabaseConfig = z.infer<typeof uriDatabaseConfig>;

const objectDatabaseConfig = z
  .object({
    host: z.string().optional(),
    port: z.number().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
    database: z.string().optional(),
  })
  .and(ssl);

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
