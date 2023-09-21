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
import { describe, expect, it, afterEach } from "vitest";

import { makeFragmentData } from "../../gql";
import { WithLocation } from "../../test-utils/WithLocation";

import BrowserSessionsOverview, { FRAGMENT } from "./BrowserSessionsOverview";

describe("BrowserSessionsOverview", () => {
  afterEach(cleanup);

  it("renders with no browser sessions", async () => {
    const user = makeFragmentData(
      {
        id: "user:123",
        browserSessions: {
          totalCount: 0,
        },
      },
      FRAGMENT,
    );
    const { container } = render(
      <WithLocation>
        <BrowserSessionsOverview user={user} />
      </WithLocation>,
    );

    expect(container).toMatchSnapshot();
  });

  it("renders with sessions", () => {
    const user = makeFragmentData(
      {
        id: "user:123",
        browserSessions: {
          totalCount: 2,
        },
      },
      FRAGMENT,
    );
    const { container } = render(
      <WithLocation>
        <BrowserSessionsOverview user={user} />
      </WithLocation>,
    );
    expect(container).toMatchSnapshot();
  });
});
