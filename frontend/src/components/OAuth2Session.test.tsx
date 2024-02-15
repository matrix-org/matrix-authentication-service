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

// @vitest-environment happy-dom

import { create } from "react-test-renderer";
import { Provider } from "urql";
import { describe, expect, it, beforeAll } from "vitest";
import { never } from "wonka";

import { makeFragmentData } from "../gql";
import { Oauth2ApplicationType } from "../gql/graphql";
import { mockLocale } from "../test-utils/mockLocale";
import { DummyRouter } from "../test-utils/router";

import OAuth2Session, { FRAGMENT } from "./OAuth2Session";

describe("<OAuth2Session />", () => {
  const mockClient = {
    executeQuery: (): typeof never => never,
  };

  const defaultSession = {
    id: "session-id",
    scope:
      "openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:abcd1234",
    createdAt: "2023-06-29T03:35:17.451292+00:00",
    lastActiveIp: "1.2.3.4",
    client: {
      id: "test-id",
      clientId: "test-client-id",
      clientName: "Element",
      clientUri: "https://element.io",
      applicationType: Oauth2ApplicationType.Web,
    },
  };

  const finishedAt = "2023-06-29T03:35:19.451292+00:00";

  beforeAll(() => mockLocale());

  it("renders an active session", () => {
    const session = makeFragmentData(defaultSession, FRAGMENT);

    const component = create(
      <Provider value={mockClient}>
        <DummyRouter>
          <OAuth2Session session={session} />
        </DummyRouter>
      </Provider>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("renders a finished session", () => {
    const session = makeFragmentData(
      {
        ...defaultSession,
        finishedAt,
      },
      FRAGMENT,
    );
    const component = create(
      <Provider value={mockClient}>
        <DummyRouter>
          <OAuth2Session session={session} />
        </DummyRouter>
      </Provider>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("renders correct icon for a native session", () => {
    const session = makeFragmentData(
      {
        ...defaultSession,
        finishedAt,
        client: {
          ...defaultSession.client,
          applicationType: Oauth2ApplicationType.Native,
        },
      },
      FRAGMENT,
    );
    const component = create(
      <Provider value={mockClient}>
        <DummyRouter>
          <OAuth2Session session={session} />
        </DummyRouter>
      </Provider>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });
});
