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
import { describe, afterEach, expect, it, beforeAll } from "vitest";

import { mockLocale } from "../../test-utils/mockLocale";

import Meta, { ActiveNow, Basic, Inactive } from "./LastActive.stories";

describe("<LastActive", () => {
  beforeAll(() => mockLocale());
  afterEach(cleanup);

  it("renders an 'active now' timestamp", () => {
    const Component = composeStory(ActiveNow, { ...Meta });
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });

  it("renders a default timestamp", () => {
    const Component = composeStory(Basic, Meta);
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });

  it("renders an inactive timestamp", () => {
    const Component = composeStory(Inactive, Meta);
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });
});
