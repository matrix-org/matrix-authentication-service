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

  const trigger = <button>Open modal</button>;

  it("does not render a closed modal", () => {
    const onConfirm = vi.fn();
    const onDeny = vi.fn();

    render(
      <ConfirmationModal
        onConfirm={onConfirm}
        onDeny={onDeny}
        className="test"
        trigger={trigger}
        title="Are you sure?"
      >
        Some extra information.
      </ConfirmationModal>,
    );
    expect(screen.getByText("Open modal")).toBeTruthy();
    expect(screen.queryByRole("alertdialog")).toBeFalsy();
  });

  it("opens modal on clicking trigger", () => {
    const onConfirm = vi.fn();
    const onDeny = vi.fn();

    render(
      <ConfirmationModal
        onConfirm={onConfirm}
        onDeny={onDeny}
        className="test"
        trigger={trigger}
        title="Are you sure?"
      >
        Some extra information.
      </ConfirmationModal>,
    );

    fireEvent.click(screen.getByText("Open modal"));

    expect(screen.getByRole("alertdialog")).toMatchSnapshot();
  });

  it("renders an undeniable modal", () => {
    const onConfirm = vi.fn();
    const onDeny = undefined;

    render(
      <ConfirmationModal
        onConfirm={onConfirm}
        onDeny={onDeny}
        className="test"
        trigger={trigger}
        title="Are you sure?"
      >
        Some extra information.
      </ConfirmationModal>,
    );

    fireEvent.click(screen.getByText("Open modal"));

    // no cancel button without onDeny
    expect(screen.queryByText("Cancel")).toBeFalsy();

    // The dialog does not close on escape
    fireEvent.keyDown(screen.getByRole("alertdialog"), {
      key: "Escape",
      code: "Escape",
      keyCode: 27,
    });

    // dialog still open
    expect(screen.queryByRole("alertdialog")).toBeTruthy();
  });

  it("calls onConfirm on confirmation", () => {
    const onConfirm = vi.fn();
    const onDeny = vi.fn();

    render(
      <ConfirmationModal
        onConfirm={onConfirm}
        onDeny={onDeny}
        className="test"
        trigger={trigger}
        title="Are you sure?"
      >
        Some extra information.
      </ConfirmationModal>,
    );

    fireEvent.click(screen.getByText("Open modal"));

    fireEvent.click(screen.getByText("Continue"));
    expect(onConfirm).toHaveBeenCalled();

    // dialog closed
    expect(screen.queryByRole("alertdialog")).toBeFalsy();
  });

  it("calls onDeny on cancel click", () => {
    const onConfirm = vi.fn();
    const onDeny = vi.fn();

    render(
      <ConfirmationModal
        onConfirm={onConfirm}
        onDeny={onDeny}
        className="test"
        trigger={trigger}
        title="Are you sure?"
      >
        Some extra information.
      </ConfirmationModal>,
    );

    fireEvent.click(screen.getByText("Open modal"));

    fireEvent.click(screen.getByText("Cancel"));
    expect(onDeny).toHaveBeenCalled();

    // dialog closed
    expect(screen.queryByRole("alertdialog")).toBeFalsy();
  });

  it("calls onDeny on closing modal via Esc", () => {
    const onConfirm = vi.fn();
    const onDeny = vi.fn();

    render(
      <ConfirmationModal
        onConfirm={onConfirm}
        onDeny={onDeny}
        className="test"
        trigger={trigger}
        title="Are you sure?"
      >
        Some extra information.
      </ConfirmationModal>,
    );

    fireEvent.click(screen.getByText("Open modal"));

    fireEvent.keyDown(screen.getByRole("alertdialog"), {
      key: "Escape",
      code: "Escape",
      keyCode: 27,
    });
    expect(onDeny).toHaveBeenCalled();

    // dialog closed
    expect(screen.queryByRole("alertdialog")).toBeFalsy();
  });
});
