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

import { createLazyFileRoute } from "@tanstack/react-router";
import { useQuery } from "urql";

import OAuth2ClientDetail from "../components/Client/OAuth2ClientDetail";
import Layout from "../components/Layout";

import { QUERY } from "./clients.$id";

export const Route = createLazyFileRoute("/clients/$id")({
  component: ClientDetail,
});

function ClientDetail(): React.ReactElement {
  const { id } = Route.useParams();
  const [result] = useQuery({
    query: QUERY,
    variables: { id },
  });
  if (result.error) throw result.error;
  const client = result.data?.oauth2Client;
  if (!client) throw new Error(); // Should have been caught by the loader

  return (
    <Layout>
      <OAuth2ClientDetail client={client} />
    </Layout>
  );
}
