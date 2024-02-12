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

import { WithLocation } from "../../test-utils/WithLocation";

import Layout from "./Layout";

describe("<Layout />", () => {
  it("renders app navigation correctly", async () => {
    const mockClient = {
      executeQuery: (): typeof never => never,
    };

    const component = render(
      <Provider value={mockClient}>
        <WithLocation path="/">
          <Layout userId="abc123" />
        </WithLocation>
      </Provider>,
    );

    expect(await component.findByText("Profile")).toMatchSnapshot();
    expect(await component.findByText("Sessions")).toMatchSnapshot();
  });
});
