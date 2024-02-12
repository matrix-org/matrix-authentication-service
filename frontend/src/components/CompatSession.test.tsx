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
import { WithLocation } from "../test-utils/WithLocation";
import { mockLocale } from "../test-utils/mockLocale";

import CompatSession, { FRAGMENT } from "./CompatSession";

describe("<CompatSession />", () => {
  const mockClient = {
    executeQuery: (): typeof never => never,
  };

  const baseSession = {
    id: "session-id",
    deviceId: "abcd1234",
    createdAt: "2023-06-29T03:35:17.451292+00:00",
    lastActiveIp: "1.2.3.4",
    ssoLogin: {
      id: "test-id",
      redirectUri: "https://element.io",
    },
  };

  const finishedAt = "2023-06-29T03:35:19.451292+00:00";

  beforeAll(() => mockLocale());

  it("renders an active session", () => {
    const session = makeFragmentData(baseSession, FRAGMENT);
    const component = create(
      <Provider value={mockClient}>
        <WithLocation>
          <CompatSession session={session} />
        </WithLocation>
      </Provider>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("renders a finished session", () => {
    const session = makeFragmentData(
      {
        ...baseSession,
        finishedAt,
      },
      FRAGMENT,
    );
    const component = create(
      <Provider value={mockClient}>
        <WithLocation>
          <CompatSession session={session} />
        </WithLocation>
      </Provider>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });
});
