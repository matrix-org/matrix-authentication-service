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

import { makeFragmentData } from "../../gql/fragment-masking";

import OAuth2ClientDetail, {
  OAUTH2_CLIENT_FRAGMENT,
} from "./OAuth2ClientDetail";

describe("<OAuth2ClientDetail>", () => {
  const baseClient = {
    id: "test-id",
    clientId: "client-id",
    clientName: "Test Client",
    clientUri: "https://client.org/logo.png",
    tosUri: "https://client.org/tos",
    policyUri: "https://client.org/policy",
    redirectUris: ["https://client.org/"],
  };
  afterEach(cleanup);

  it("renders client details", () => {
    const data = makeFragmentData(baseClient, OAUTH2_CLIENT_FRAGMENT);

    const { container } = render(<OAuth2ClientDetail client={data} />);

    expect(container).toMatchSnapshot();
  });

  it("does not render terms of service when falsy", () => {
    const data = makeFragmentData(
      {
        ...baseClient,
        tosUri: undefined,
      },
      OAUTH2_CLIENT_FRAGMENT,
    );

    const { queryByText } = render(<OAuth2ClientDetail client={data} />);

    expect(queryByText("Terms of service")).toBeFalsy();
  });

  it("does not render logo when logoUri is falsy", () => {
    const data = makeFragmentData(
      {
        ...baseClient,
        logoUri: undefined,
      },
      OAUTH2_CLIENT_FRAGMENT,
    );

    const { queryByAltText } = render(<OAuth2ClientDetail client={data} />);

    expect(queryByAltText(baseClient.clientName)).toBeFalsy();
  });
});
