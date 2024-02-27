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

import { Outlet, createFileRoute, notFound } from "@tanstack/react-router";
import { Heading } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import { useEndBrowserSession } from "../components/BrowserSession";
import Layout from "../components/Layout";
import NavBar from "../components/NavBar";
import NavItem from "../components/NavItem";
import EndSessionButton from "../components/Session/EndSessionButton";
import UnverifiedEmailAlert from "../components/UnverifiedEmailAlert";
import UserGreeting from "../components/UserGreeting";
import { graphql } from "../gql";

const QUERY = graphql(/* GraphQL */ `
  query CurrentUserGreeting {
    viewerSession {
      __typename

      ... on BrowserSession {
        id

        user {
          id
          ...UnverifiedEmailAlert_user
          ...UserGreeting_user
        }
      }
    }
  }
`);

export const Route = createFileRoute("/_account")({
  loader: async ({ context, abortController: { signal } }) => {
    const result = await context.client.query(
      QUERY,
      {},
      { fetchOptions: { signal } },
    );
    if (result.error) throw result.error;
    if (result.data?.viewerSession.__typename !== "BrowserSession")
      throw notFound();
  },
  component: Account,
});

function Account(): React.ReactElement {
  const { t } = useTranslation();
  const [result] = useQuery({
    query: QUERY,
  });
  if (result.error) throw result.error;
  const session = result.data?.viewerSession;
  if (session?.__typename !== "BrowserSession") throw notFound();
  const onSessionEnd = useEndBrowserSession(session.id, true);

  return (
    <Layout wide>
      <div className="flex flex-col gap-4">
        <header className="flex justify-between mb-4">
          <Heading size="lg" weight="semibold">
            {t("frontend.account.title")}
          </Heading>

          <EndSessionButton endSession={onSessionEnd} />
        </header>

        <UserGreeting user={session.user} />

        <UnverifiedEmailAlert user={session.user} />

        <NavBar>
          <NavItem from={Route.fullPath} to=".">
            {t("frontend.nav.settings")}
          </NavItem>
          <NavItem from={Route.fullPath} to="./sessions">
            {t("frontend.nav.devices")}
          </NavItem>
        </NavBar>
      </div>

      <Outlet />
    </Layout>
  );
}
