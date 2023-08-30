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

import { render, cleanup, fireEvent } from "@testing-library/react";
import { describe, it, expect, afterEach } from "vitest";

import { makeFragmentData } from "../../gql/fragment-masking";
import { WithLocation } from "../../test-utils/WithLocation";

import UnverifiedEmailAlert, {
  UNVERIFIED_EMAILS_FRAGMENT,
} from "./UnverifiedEmailAlert";

describe("<UnverifiedEmailAlert />", () => {
  afterEach(cleanup);

  it("does not render a warning when there are no unverified emails", () => {
    const data = makeFragmentData(
      {
        id: "abc123",
        unverifiedEmails: {
          totalCount: 0,
        },
      },
      UNVERIFIED_EMAILS_FRAGMENT,
    );

    const { container } = render(
      <WithLocation>
        <UnverifiedEmailAlert unverifiedEmails={data} />
      </WithLocation>,
    );

    expect(container).toMatchInlineSnapshot("<div />");
  });

  it("renders a warning when there are unverified emails", () => {
    const data = makeFragmentData(
      {
        id: "abc123",
        unverifiedEmails: {
          totalCount: 2,
        },
      },
      UNVERIFIED_EMAILS_FRAGMENT,
    );

    const { container } = render(
      <WithLocation>
        <UnverifiedEmailAlert unverifiedEmails={data} />
      </WithLocation>,
    );

    expect(container).toMatchSnapshot();
  });

  it("hides warning after it has been dismissed", () => {
    const data = makeFragmentData(
      {
        id: "abc123",
        unverifiedEmails: {
          totalCount: 2,
        },
      },
      UNVERIFIED_EMAILS_FRAGMENT,
    );

    const { container, getByText, getByLabelText } = render(
      <WithLocation>
        <UnverifiedEmailAlert unverifiedEmails={data} />
      </WithLocation>,
    );

    // warning is rendered
    expect(getByText("Unverified email")).toBeTruthy();

    fireEvent.click(getByLabelText("Close"));

    // no more warning
    expect(container).toMatchInlineSnapshot("<div />");
  });
});
