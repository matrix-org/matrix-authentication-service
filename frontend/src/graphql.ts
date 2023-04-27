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

import { createClient, fetchExchange } from "@urql/core";
import { cacheExchange } from "@urql/exchange-graphcache";
import { devtoolsExchange } from "@urql/devtools";
import { refocusExchange } from "@urql/exchange-refocus";

import schema from "./gql/schema";
import type { MutationAddEmailArgs } from "./gql/graphql";
import { requestPolicyExchange } from "@urql/exchange-request-policy";

const cache = cacheExchange({
  schema,
  updates: {
    Mutation: {
      addEmail: (result, args: MutationAddEmailArgs, cache, _info) => {
        const key = cache.keyOfEntity({
          __typename: "User",
          id: args.input.userId,
        });

        // Invalidate the emails field on the User object so that it gets refetched
        cache
          .inspectFields(key)
          .filter((field) => field.fieldName === "emails")
          .forEach((field) => {
            cache.invalidate(key, field.fieldName, field.arguments);
          });
      },
    },
  },
});

const exchanges = [
  // This sets the policy to 'cache-and-network' after 5 minutes
  requestPolicyExchange({
    ttl: 1000 * 60 * 5, // 5 minute
  }),

  // This refetches all queries when the tab is refocused
  refocusExchange(),

  // The unified cache
  cache,

  // Use `fetch` to execute the requests
  fetchExchange,
];

export const client = createClient({
  url: "/graphql",
  // Add the devtools exchange in development
  exchanges: import.meta.env.DEV ? [devtoolsExchange, ...exchanges] : exchanges,
});
