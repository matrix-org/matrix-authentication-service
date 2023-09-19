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

import { render, cleanup, screen } from "@testing-library/react";
import { describe, expect, it, afterEach } from "vitest";

import { makeFragmentData } from "../../gql/fragment-masking";
import { WithLocation } from "../../test-utils/WithLocation";

import UserEmail, { FRAGMENT } from "./UserEmail";

describe("<UserEmail />", () => {
  afterEach(cleanup);

  const baseEmail = {
    id: "testid",
    email: "ernie@sesame.st",
  };

  it("renders a basic email", () => {
    const email = makeFragmentData(baseEmail, FRAGMENT);
    const { container } = render(
      <WithLocation>
        <UserEmail email={email} />
      </WithLocation>,
    );

    expect(container).toMatchSnapshot();
  });

  it("renders a primary email", () => {
    const email = makeFragmentData(baseEmail, FRAGMENT);
    render(
      <WithLocation>
        <UserEmail email={email} isPrimary={true} />
      </WithLocation>,
    );

    // uses primary email label
    expect(screen.getByText("Primary email")).toBeTruthy();
    // no make primary button
    expect(screen.queryByText("Make primary")).toBeFalsy();
    // cannot be removed
    expect(
      screen.getByLabelText("Remove email address").hasAttribute("disabled"),
    ).toBeTruthy();
  });

  it("renders a confirmed email", () => {
    const email = makeFragmentData(
      {
        ...baseEmail,
        confirmedAt: "2023-07-29T03:35:17.451292+00:00",
      },
      FRAGMENT,
    );
    render(
      <WithLocation>
        <UserEmail email={email} />
      </WithLocation>,
    );

    // has make primary button
    expect(screen.getByText("Make primary")).toBeTruthy();
  });

  describe("read only emails", () => {
    it("renders a basic email", () => {
      const email = makeFragmentData(baseEmail, FRAGMENT);
      render(
        <WithLocation>
          <UserEmail email={email} isReadOnly />
        </WithLocation>,
      );

      expect(screen.queryByLabelText("Remove email address")).toBeFalsy();
      // can still verify
      expect(screen.getByText("Retry verification")).toBeTruthy();
    });

    it("renders a primary email", () => {
      const email = makeFragmentData(baseEmail, FRAGMENT);
      render(
        <WithLocation>
          <UserEmail email={email} isReadOnly isPrimary={true} />
        </WithLocation>,
      );

      // cannot be removed
      expect(screen.queryByLabelText("Remove email address")).toBeFalsy();
    });

    it("renders a confirmed email", () => {
      const email = makeFragmentData(
        {
          ...baseEmail,
          confirmedAt: "2023-07-29T03:35:17.451292+00:00",
        },
        FRAGMENT,
      );
      render(
        <WithLocation>
          <UserEmail email={email} isReadOnly />
        </WithLocation>,
      );

      // no remove button
      expect(screen.queryByLabelText("Remove email address")).toBeFalsy();
      // no make primary button
      expect(screen.queryByText("Make primary")).toBeFalsy();
    });
  });
});
