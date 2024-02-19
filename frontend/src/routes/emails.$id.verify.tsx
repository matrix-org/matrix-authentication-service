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

import { createFileRoute, notFound } from "@tanstack/react-router";
import { useQuery } from "urql";

import Layout from "../components/Layout";
import VerifyEmailComponent from "../components/VerifyEmail";
import { graphql } from "../gql";

const QUERY = graphql(/* GraphQL */ `
  query VerifyEmailQuery($id: ID!) {
    userEmail(id: $id) {
      ...UserEmail_verifyEmail
    }
  }
`);

export const Route = createFileRoute("/emails/$id/verify")({
  async loader({ context, params, abortController: { signal } }) {
    const result = await context.client.query(
      QUERY,
      {
        id: params.id,
      },
      { fetchOptions: { signal } },
    );
    if (result.error) throw result.error;
    if (!result.data?.userEmail) throw notFound();
  },

  component: EmailVerify,
});

function EmailVerify(): React.ReactElement {
  const { id } = Route.useParams();
  const [result] = useQuery({ query: QUERY, variables: { id } });

  if (result.error) throw result.error;
  const email = result.data?.userEmail;
  if (email == null) throw notFound();

  return (
    <Layout>
      <VerifyEmailComponent email={email} />
    </Layout>
  );
}
