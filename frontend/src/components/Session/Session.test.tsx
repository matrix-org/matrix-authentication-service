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

import { parseISO } from "date-fns";
import { create } from "react-test-renderer";
import { describe, expect, it, beforeAll } from "vitest";

import { mockLocale } from "../../test-utils/mockLocale";
import { DummyRouter } from "../../test-utils/router";

import Session from "./Session";

describe("<Session />", () => {
  const defaultProps = {
    id: "session-id",
    createdAt: parseISO("2023-06-29T03:35:17.451292+00:00"),
  };

  const finishedAt = parseISO("2023-06-29T03:35:19.451292+00:00");

  beforeAll(() => mockLocale());

  it("renders an active session", () => {
    const component = create(
      <DummyRouter>
        <Session {...defaultProps} />
      </DummyRouter>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("renders a finished session", () => {
    const component = create(
      <DummyRouter>
        <Session {...defaultProps} finishedAt={finishedAt} />
      </DummyRouter>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("uses session name when truthy", () => {
    const name = "test session name";
    const component = create(
      <DummyRouter>
        <Session {...defaultProps} finishedAt={finishedAt} name={name} />
      </DummyRouter>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("uses client name when truthy", () => {
    const clientName = "Element";
    const component = create(
      <DummyRouter>
        <Session
          {...defaultProps}
          finishedAt={finishedAt}
          clientName={clientName}
          clientLogoUri="https://client.org/logo.png"
        />
      </DummyRouter>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("renders ip address", () => {
    const clientName = "Element";
    const component = create(
      <DummyRouter>
        <Session
          {...defaultProps}
          finishedAt={finishedAt}
          clientName={clientName}
          lastActiveIp="127.0.0.1"
        />
      </DummyRouter>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });
});
