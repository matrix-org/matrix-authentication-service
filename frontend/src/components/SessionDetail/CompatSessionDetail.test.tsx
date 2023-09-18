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
import { describe, expect, it, afterEach, beforeAll } from "vitest";

import { makeFragmentData } from "../../gql/fragment-masking";
import { WithLocation } from "../../test-utils/WithLocation";
import { mockLocale } from "../../test-utils/mockLocale";
import { COMPAT_SESSION_FRAGMENT } from "../CompatSession";

import CompatSessionDetail from "./CompatSessionDetail";

describe("<CompatSessionDetail>", () => {
  const baseSession = {
    id: "session-id",
    deviceId: "abcd1234",
    createdAt: "2023-06-29T03:35:17.451292+00:00",
    ssoLogin: {
      id: "test-id",
      redirectUri: "https://element.io",
    },
  };

  beforeAll(() => mockLocale());
  afterEach(cleanup);

  it("renders a compatability session details", () => {
    const data = makeFragmentData(baseSession, COMPAT_SESSION_FRAGMENT);

    const { container } = render(
      <WithLocation>
        <CompatSessionDetail session={data} />
      </WithLocation>,
    );

    expect(container).toMatchSnapshot();
  });

  it("renders a compatability session without an ssoLogin redirectUri", () => {
    const data = makeFragmentData(
      {
        ...baseSession,
        ssoLogin: {
          id: "dfsdjfdk",
          redirectUri: undefined,
        },
      },
      COMPAT_SESSION_FRAGMENT,
    );

    const { container } = render(
      <WithLocation>
        <CompatSessionDetail session={data} />
      </WithLocation>,
    );

    expect(container).toMatchSnapshot();
  });

  it("renders a finished compatability session details", () => {
    const data = makeFragmentData(
      {
        ...baseSession,
        finishedAt: "2023-07-29T03:35:17.451292+00:00",
      },
      COMPAT_SESSION_FRAGMENT,
    );

    const { getByText, queryByText } = render(
      <WithLocation>
        <CompatSessionDetail session={data} />
      </WithLocation>,
    );

    expect(getByText("Finished")).toBeTruthy();
    // no end session button
    expect(queryByText("End session")).toBeFalsy();
  });
});
