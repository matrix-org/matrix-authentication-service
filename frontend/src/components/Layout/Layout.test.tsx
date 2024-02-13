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

import { render } from "@testing-library/react";
import { Provider } from "urql";
import { describe, expect, it } from "vitest";
import { never } from "wonka";

import { makeFragmentData } from "../../gql";
import { DummyRouter } from "../../test-utils/router";
import { USER_GREETING_FRAGMENT } from "../UserGreeting";

import Layout from "./Layout";

describe("<Layout />", () => {
  it("renders app navigation correctly", async () => {
    const mockClient = {
      executeQuery: (): typeof never => never,
    };

    const user = makeFragmentData(
      {
        id: "abc123",
        username: "alice",
        matrix: {
          mxid: "@alice:example.org",
          displayName: "Alice",
        },
      },
      USER_GREETING_FRAGMENT,
    );

    const component = render(
      <Provider value={mockClient}>
        <DummyRouter>
          <Layout user={user} />
        </DummyRouter>
      </Provider>,
    );

    expect(await component.findByText("Profile")).toMatchSnapshot();
    expect(await component.findByText("Sessions")).toMatchSnapshot();
  });
});
