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

import { render, cleanup, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, afterEach, vi } from "vitest";

import ConfirmationModal from "./ConfirmationModal";

describe("<ConfirmationModal />", () => {
  afterEach(cleanup);

  it("does not render a closed modal", () => {
    const onConfirm = vi.fn();
    const onDeny = vi.fn();

    render(
      <ConfirmationModal
        isOpen={false}
        onConfirm={onConfirm}
        onDeny={onDeny}
        className="test"
        data-testid="test"
      >
        Are you sure?
      </ConfirmationModal>,
    );
    expect(screen.queryByRole("dialog")).toBeFalsy();
  });

  it("renders a modal with confirm and deny buttons", () => {
    const onConfirm = vi.fn();
    const onDeny = vi.fn();

    render(
      <ConfirmationModal
        isOpen={true}
        onConfirm={onConfirm}
        onDeny={onDeny}
        className="test"
        data-testid="test"
      >
        Are you sure?
      </ConfirmationModal>,
    );
    expect(screen.getByRole("dialog")).toMatchSnapshot();
  });

  it("renders an undeniable modal", () => {
    const onConfirm = vi.fn();
    const onDeny = undefined;

    render(
      <ConfirmationModal
        isOpen={true}
        onConfirm={onConfirm}
        onDeny={onDeny}
        className="test"
        data-testid="test"
      >
        Are you sure?
      </ConfirmationModal>,
    );

    // no cancel button without onDeny
    expect(screen.queryByText("Cancel")).toBeFalsy();
  });

  it("calls onConfirm on confirmation", () => {
    const onConfirm = vi.fn();
    const onDeny = vi.fn();

    render(
      <ConfirmationModal
        isOpen={true}
        onConfirm={onConfirm}
        onDeny={onDeny}
        className="test"
        data-testid="test"
      >
        Are you sure?
      </ConfirmationModal>,
    );

    fireEvent.click(screen.getByText("Continue"));
    expect(onConfirm).toHaveBeenCalled();
  });

  it("calls onDeny on cancel click", () => {
    const onConfirm = vi.fn();
    const onDeny = vi.fn();

    render(
      <ConfirmationModal
        isOpen={true}
        onConfirm={onConfirm}
        onDeny={onDeny}
        className="test"
        data-testid="test"
      >
        Are you sure?
      </ConfirmationModal>,
    );

    fireEvent.click(screen.getByText("Cancel"));
    expect(onDeny).toHaveBeenCalled();
  });

  it("calls onDeny on closing modal via Esc", () => {
    const onConfirm = vi.fn();
    const onDeny = vi.fn();

    render(
      <ConfirmationModal
        isOpen={true}
        onConfirm={onConfirm}
        onDeny={onDeny}
        className="test"
        data-testid="test"
      >
        Are you sure?
      </ConfirmationModal>,
    );

    fireEvent.keyDown(screen.getByRole("dialog"), {
      key: "Escape",
      code: "Escape",
      keyCode: 27,
    });
    expect(onDeny).toHaveBeenCalled();
  });
});
