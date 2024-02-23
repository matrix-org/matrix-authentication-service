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

import { composeStory } from "@storybook/react";
import { render, cleanup } from "@testing-library/react";
import { describe, it, expect, afterEach } from "vitest";

import Meta, { Unknown, Pc, Mobile, Tablet } from "./DeviceTypeIcon.stories";

describe("<DeviceTypeIcon />", () => {
  afterEach(cleanup);

  it("renders unknown device type", () => {
    const Component = composeStory(Unknown, Meta);
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });
  it("renders mobile device type", () => {
    const Component = composeStory(Mobile, Meta);
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });
  it("renders pc device type", () => {
    const Component = composeStory(Pc, Meta);
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });
  it("renders tablet device type", () => {
    const Component = composeStory(Tablet, Meta);
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });
});
