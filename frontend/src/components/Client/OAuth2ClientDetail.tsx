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

import { H3 } from "@vector-im/compound-web";

import { FragmentType, useFragment } from "../../gql";
import { graphql } from "../../gql/gql";
import BlockList from "../BlockList/BlockList";
import ExternalLink from "../ExternalLink/ExternalLink";
import ClientAvatar from "../Session/ClientAvatar";
import SessionDetails from "../SessionDetail/SessionDetails";

import styles from "./OAuth2ClientDetail.module.css";

export const OAUTH2_CLIENT_FRAGMENT = graphql(/* GraphQL */ `
  fragment OAuth2Client_detail on Oauth2Client {
    id
    clientId
    clientName
    clientUri
    logoUri
    tosUri
    policyUri
    redirectUris
  }
`);

type Props = {
  client: FragmentType<typeof OAUTH2_CLIENT_FRAGMENT>;
};

const FriendlyExternalLink: React.FC<{ uri?: string }> = ({ uri }) => {
  if (!uri) {
    return null;
  }
  const url = new URL(uri);
  const friendlyUrl = url.host + url.pathname;

  return <ExternalLink href={uri}>{friendlyUrl}</ExternalLink>;
};

const OAuth2ClientDetail: React.FC<Props> = ({ client }) => {
  const data = useFragment(OAUTH2_CLIENT_FRAGMENT, client);

  const details = [
    { label: "Name", value: data.clientName },
    { label: "Client ID", value: <code>{data.clientId}</code> },
    {
      label: "Terms of service",
      value: data.tosUri && <FriendlyExternalLink uri={data.tosUri} />,
    },
    {
      label: "Policy",
      value: data.policyUri && <FriendlyExternalLink uri={data.policyUri} />,
    },
  ].filter(({ value }) => !!value);

  return (
    <BlockList>
      <header className={styles.header}>
        <ClientAvatar
          logoUri={data.logoUri || undefined}
          name={data.clientName || data.clientId}
          size="1.5rem"
        />
        <H3>{data.clientName}</H3>
      </header>
      <SessionDetails title="Client" details={details} />
    </BlockList>
  );
};

export default OAuth2ClientDetail;
