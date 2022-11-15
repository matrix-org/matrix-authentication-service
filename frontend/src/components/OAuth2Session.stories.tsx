// Copyright 2022 The Matrix.org Foundation C.I.C.
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

import type { Meta, StoryObj } from "@storybook/react";
import {
  graphql,
  RelayEnvironmentProvider,
  useLazyLoadQuery,
} from "react-relay";
import { createMockEnvironment, MockPayloadGenerator } from "relay-test-utils";

import OAuth2Session from "./OAuth2Session";
import { OAuth2SessionStoriesQuery } from "./__generated__/OAuth2SessionStoriesQuery.graphql";

type TemplateProps = {
  scope: string;
  clientId: string;
  clientName: string;
  clientUri: string;
};

const Template: React.FC<TemplateProps> = ({
  scope,
  clientId,
  clientName,
  clientUri,
}) => {
  const environment = createMockEnvironment();
  environment.mock.queueOperationResolver((operation) =>
    MockPayloadGenerator.generate(operation, {
      Oauth2Session() {
        return {
          scope,
        };
      },

      Oauth2Client() {
        return {
          clientId,
          clientName,
          clientUri,
        };
      },
    })
  );

  const Render = () => {
    const data = useLazyLoadQuery<OAuth2SessionStoriesQuery>(
      graphql`
        query OAuth2SessionStoriesQuery @relay_test_operation {
          session: node(id: "test-id") {
            ...OAuth2Session_session
          }
        }
      `,
      {}
    );

    return <OAuth2Session session={data.session!!} />;
  };

  return (
    <RelayEnvironmentProvider environment={environment}>
      <Render />
    </RelayEnvironmentProvider>
  );
};

const meta: Meta<typeof Template> = {
  title: "Components/OAuth 2.0 Session",
  component: Template,
  tags: ["docsPage"],
  args: {
    scope: "openid",
    clientId: "aaabbbcccdddeee",
    clientName: "My client",
    clientUri: "https://example.com/",
  },
};

export default meta;
type Story = StoryObj<typeof Template>;

export const Basic: Story = {};
