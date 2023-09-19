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
import { describe, expect, it, beforeAll } from "vitest";

import { FragmentType } from "../gql/fragment-masking";
import { WithLocation } from "../test-utils/WithLocation";
import { mockLocale } from "../test-utils/mockLocale";

import OAuth2Session, { OAUTH2_SESSION_FRAGMENT } from "./OAuth2Session";

describe("<OAuth2Session />", () => {
  const defaultProps = {
    session: {
      id: "session-id",
      scope:
        "openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:abcd1234",
      createdAt: "2023-06-29T03:35:17.451292+00:00",
      client: {
        id: "test-id",
        clientId: "test-client-id",
        clientName: "Element",
        clientUri: "https://element.io",
      },
    } as FragmentType<typeof OAUTH2_SESSION_FRAGMENT>,
  };

  const finishedAt = "2023-06-29T03:35:19.451292+00:00";

  beforeAll(() => mockLocale());

  it("renders an active session", () => {
    const component = create(
      <WithLocation>
        <OAuth2Session {...defaultProps} />
      </WithLocation>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("renders a finished session", () => {
    const finishedSession = {
      ...defaultProps.session,
      finishedAt,
    };
    const component = create(
      <WithLocation>
        <OAuth2Session session={finishedSession} />
      </WithLocation>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });
});
