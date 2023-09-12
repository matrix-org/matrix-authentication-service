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
import { describe, it, vi, expect, afterEach } from "vitest";

import SelectableSession from "./SelectableSession";

describe("<SelectableSession />", () => {
  afterEach(cleanup);

  it("renders an unselected session", () => {
    const onSelect = vi.fn();
    const { container } = render(
      <SelectableSession isSelected={false} onSelect={onSelect}>
        <div>Test child</div>
      </SelectableSession>,
    );
    expect(container).toMatchSnapshot();
  });

  it("calls onchange when checkbox is clicked", () => {
    const onSelect = vi.fn();
    const { getByLabelText } = render(
      <SelectableSession isSelected={true} onSelect={onSelect}>
        <div>Test child</div>
      </SelectableSession>,
    );
    fireEvent.click(getByLabelText("Select session"));

    expect(onSelect).toHaveBeenCalled();
  });
});
