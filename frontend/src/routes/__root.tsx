// Copyright 2024 The Matrix.org Foundation C.I.C.
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

import {
  createRootRouteWithContext,
  Outlet,
  redirect,
} from "@tanstack/react-router";
import { TanStackRouterDevtools } from "@tanstack/router-devtools";
import { Client } from "urql";
import { z } from "zod";

import Layout from "../components/Layout";
import NotFound from "../components/NotFound";

const actionSchema = z
  .discriminatedUnion("action", [
    z.object({
      action: z.enum(["profile", "org.matrix.profile"]),
    }),
    z.object({
      action: z.enum(["sessions_list", "org.matrix.sessions_list"]),
    }),
    z.object({
      action: z.enum(["session_view", "org.matrix.session_view"]),
      device_id: z.string().optional(),
    }),
    z.object({
      action: z.enum(["session_end", "org.matrix.session_end"]),
      device_id: z.string().optional(),
    }),
    z.object({
      action: z.literal("org.matrix.cross_signing_reset"),
    }),
    z.object({
      action: z.undefined(),
    }),
  ])
  .catch({ action: undefined });

export const Route = createRootRouteWithContext<{
  client: Client;
}>()({
  validateSearch: actionSchema,

  beforeLoad({ search }) {
    switch (search.action) {
      case "profile":
      case "org.matrix.profile":
        throw redirect({ to: "/" });

      case "sessions_list":
      case "org.matrix.sessions_list":
        throw redirect({ to: "/sessions" });

      case "session_view":
      case "org.matrix.session_view":
        if (search.device_id)
          throw redirect({
            to: "/devices/$id",
            params: { id: search.device_id },
          });
        throw redirect({ to: "/sessions" });

      case "session_end":
      case "org.matrix.session_end":
        if (search.device_id)
          throw redirect({
            to: "/devices/$id",
            params: { id: search.device_id },
          });
        throw redirect({ to: "/sessions" });

      case "org.matrix.cross_signing_reset":
        throw redirect({
          to: "/reset-cross-signing",
          search: { deepLink: true },
        });
    }
  },

  component: () => (
    <>
      <Outlet />
      {import.meta.env.DEV && <TanStackRouterDevtools />}
    </>
  ),

  notFoundComponent: () => (
    <Layout>
      <NotFound />
    </Layout>
  ),
});
