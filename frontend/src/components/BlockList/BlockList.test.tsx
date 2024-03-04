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

import { create } from "react-test-renderer";
import { describe, expect, it } from "vitest";

import Block from "../Block";

import BlockList from "./BlockList";

describe("BlockList", () => {
  it("render an empty <BlockList />", () => {
    const component = create(<BlockList />);
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("render <BlockList /> with children", () => {
    const component = create(
      <BlockList>
        <Block>Block 1</Block>
        <Block>Block 2</Block>
      </BlockList>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("passes down the className prop", () => {
    const component = create(<BlockList className="foo" />);
    expect(component.toJSON()).toMatchSnapshot();
  });
});
