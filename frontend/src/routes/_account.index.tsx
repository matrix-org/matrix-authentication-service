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
import IconKey from "@vector-im/compound-design-tokens/icons/key.svg?react";
import { H3, Separator } from "@vector-im/compound-web";
import { Suspense } from "react";
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import BlockList from "../components/BlockList/BlockList";
import { ButtonLink } from "../components/ButtonLink";
import LoadingSpinner from "../components/LoadingSpinner";
import UserEmailList from "../components/UserProfile/UserEmailList";
import UserName from "../components/UserProfile/UserName";
import { graphql } from "../gql";

const QUERY = graphql(/* GraphQL */ `
  query UserProfileQuery {
    viewer {
      __typename
      ... on User {
        id
        ...UserName_user
        ...UserEmailList_user
      }
    }
  }
`);

export const Route = createFileRoute("/_account/")({
  async loader({ context, abortController: { signal } }) {
    const result = await context.client.query(
      QUERY,
      {},
      { fetchOptions: { signal } },
    );
    if (result.error) throw result.error;
    if (result.data?.viewer.__typename !== "User") throw notFound();
  },
  component: Index,
});

function Index(): React.ReactElement {
  const { t } = useTranslation();
  const [result] = useQuery({ query: QUERY });
  if (result.error) throw result.error;
  const user = result.data?.viewer;
  if (user?.__typename !== "User") throw notFound();

  return (
    <>
      <BlockList>
        <UserName user={user} />

        <BlockList>
          <H3 id="emails">{t("frontend.user_email_list.heading")}</H3>
          <Suspense fallback={<LoadingSpinner className="self-center m-4" />}>
            <UserEmailList user={user} />
          </Suspense>
        </BlockList>

        <Separator />

        <ButtonLink
          to="/reset-cross-signing"
          kind="tertiary"
          destructive
          Icon={IconKey}
        >
          {t("frontend.reset_cross_signing.heading")}
        </ButtonLink>
      </BlockList>
    </>
  );
}
