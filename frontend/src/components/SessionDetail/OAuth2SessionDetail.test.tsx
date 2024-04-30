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

import { render, cleanup } from "@testing-library/react";
import { Provider } from "urql";
import { describe, expect, it, afterEach, beforeAll } from "vitest";
import { never } from "wonka";

import { makeFragmentData } from "../../gql";
import { mockLocale } from "../../test-utils/mockLocale";
import { DummyRouter } from "../../test-utils/router";

import OAuth2SessionDetail, { FRAGMENT } from "./OAuth2SessionDetail";

describe("<OAuth2SessionDetail>", () => {
  const mockClient = {
    executeQuery: (): typeof never => never,
  };

  const baseSession = {
    id: "session-id",
    scope:
      "openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:abcd1234",
    createdAt: "2023-06-29T03:35:17.451292+00:00",
    finishedAt: null,
    lastActiveAt: "2023-07-29T03:35:17.451292+00:00",
    lastActiveIp: "1.2.3.4",
    userAgent: null,
    client: {
      id: "test-id",
      clientId: "test-client-id",
      clientName: "Element",
      clientUri: "https://element.io",
      logoUri: null,
    },
  };

  beforeAll(() => mockLocale());
  afterEach(cleanup);

  it("renders session details", () => {
    const data = makeFragmentData(baseSession, FRAGMENT);

    const { asFragment, getByText, queryByText } = render(
      <Provider value={mockClient}>
        <DummyRouter>
          <OAuth2SessionDetail session={data} />
        </DummyRouter>
      </Provider>,
    );

    expect(asFragment()).toMatchSnapshot();
    expect(queryByText("Finished")).toBeFalsy();
    expect(getByText("Sign out")).toBeTruthy();
  });

  it("renders a finished session details", () => {
    const data = makeFragmentData(
      {
        ...baseSession,
        finishedAt: "2023-07-29T03:35:17.451292+00:00",
      },
      FRAGMENT,
    );

    const { asFragment, getByText, queryByText } = render(
      <Provider value={mockClient}>
        <DummyRouter>
          <OAuth2SessionDetail session={data} />
        </DummyRouter>
      </Provider>,
    );

    expect(asFragment()).toMatchSnapshot();
    expect(getByText("Finished")).toBeTruthy();
    expect(queryByText("Sign out")).toBeFalsy();
  });
});
