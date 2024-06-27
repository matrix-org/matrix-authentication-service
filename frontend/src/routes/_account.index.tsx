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

import { createFileRoute, notFound, useNavigate } from "@tanstack/react-router";
import IconKey from "@vector-im/compound-design-tokens/icons/key.svg?react";
import { Alert, Separator } from "@vector-im/compound-web";
import { Suspense } from "react";
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import AccountManagementPasswordPreview from "../components/AccountManagementPasswordPreview";
import BlockList from "../components/BlockList/BlockList";
import { ButtonLink } from "../components/ButtonLink";
import LoadingSpinner from "../components/LoadingSpinner";
import UserEmail from "../components/UserEmail";
import AddEmailForm from "../components/UserProfile/AddEmailForm";
import UserEmailList from "../components/UserProfile/UserEmailList";
import { graphql } from "../gql";

const QUERY = graphql(/* GraphQL */ `
  query UserProfileQuery {
    viewer {
      __typename
      ... on User {
        id

        primaryEmail {
          id
          ...UserEmail_email
        }

        ...UserEmailList_user
      }
    }

    siteConfig {
      id
      emailChangeAllowed
      passwordLoginEnabled
      ...UserEmailList_siteConfig
      ...UserEmail_siteConfig
      ...PasswordChange_siteConfig
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
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [result] = useQuery({ query: QUERY });
  if (result.error) throw result.error;
  const user = result.data?.viewer;
  if (user?.__typename !== "User") throw notFound();
  const siteConfig = result.data?.siteConfig;
  if (!siteConfig) throw Error(); // This should never happen

  // When adding an email, we want to go to the email verification form
  const onAdd = async (id: string): Promise<void> => {
    await navigate({ to: "/emails/$id/verify", params: { id } });
  };

  return (
    <>
      <BlockList>
        {/* This wrapper is only needed for the anchor link */}
        <div className="flex flex-col gap-4" id="emails">
          {user.primaryEmail ? (
            <UserEmail
              email={user.primaryEmail}
              isPrimary
              siteConfig={siteConfig}
            />
          ) : (
            <Alert
              type="critical"
              title={t("frontend.user_email_list.no_primary_email_alert")}
            />
          )}

          <Suspense fallback={<LoadingSpinner mini className="self-center" />}>
            <UserEmailList siteConfig={siteConfig} user={user} />
          </Suspense>

          {siteConfig.emailChangeAllowed && (
            <AddEmailForm userId={user.id} onAdd={onAdd} />
          )}
        </div>

        <Separator />

        {siteConfig.passwordLoginEnabled && (
          <AccountManagementPasswordPreview siteConfig={siteConfig} />
        )}

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
