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
import { TooltipProvider } from "@vector-im/compound-web";
import { Provider } from "urql";
import { describe, expect, it, afterEach, beforeAll } from "vitest";
import { never } from "wonka";

import { makeFragmentData } from "../../gql";
import { mockLocale } from "../../test-utils/mockLocale";
import { DummyRouter } from "../../test-utils/router";

import CompatSessionDetail, { FRAGMENT } from "./CompatSessionDetail";

describe("<CompatSessionDetail>", () => {
  const mockClient = {
    executeQuery: (): typeof never => never,
  };

  const baseSession = {
    id: "session-id",
    deviceId: "abcd1234",
    createdAt: "2023-06-29T03:35:17.451292+00:00",
    finishedAt: null,
    lastActiveIp: "1.2.3.4",
    lastActiveAt: "2023-07-29T03:35:17.451292+00:00",
    userAgent: null,
    ssoLogin: {
      id: "test-id",
      redirectUri: "https://element.io",
    },
  };

  beforeAll(() => mockLocale());
  afterEach(cleanup);

  it("renders a compatability session details", () => {
    const data = makeFragmentData({ ...baseSession }, FRAGMENT);

    const { container, getByText, queryByText } = render(
      <TooltipProvider>
        <Provider value={mockClient}>
          <DummyRouter>
            <CompatSessionDetail session={data} />
          </DummyRouter>
        </Provider>
      </TooltipProvider>,
    );

    expect(container).toMatchSnapshot();
    expect(queryByText("Finished")).toBeFalsy();
    expect(getByText("Sign out")).toBeTruthy();
  });

  it("renders a compatability session without an ssoLogin", () => {
    const data = makeFragmentData(
      {
        ...baseSession,
        ssoLogin: null,
      },
      FRAGMENT,
    );

    const { container, getByText, queryByText } = render(
      <Provider value={mockClient}>
        <DummyRouter>
          <CompatSessionDetail session={data} />
        </DummyRouter>
      </Provider>,
    );

    expect(container).toMatchSnapshot();
    expect(queryByText("Finished")).toBeFalsy();
    expect(getByText("Sign out")).toBeTruthy();
  });

  it("renders a finished compatability session details", () => {
    const data = makeFragmentData(
      {
        ...baseSession,
        finishedAt: "2023-07-29T03:35:17.451292+00:00",
      },
      FRAGMENT,
    );

    const { container, getByText, queryByText } = render(
      <Provider value={mockClient}>
        <DummyRouter>
          <CompatSessionDetail session={data} />
        </DummyRouter>
      </Provider>,
    );

    expect(container).toMatchSnapshot();
    expect(getByText("Finished")).toBeTruthy();
    expect(queryByText("Sign out")).toBeFalsy();
  });
});
