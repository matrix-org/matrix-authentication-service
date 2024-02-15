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
import { TooltipProvider } from "@vector-im/compound-web";
import { describe, expect, it, afterEach, vi } from "vitest";

import ConfirmationModal from "./ConfirmationModal";

describe("<ConfirmationModal />", () => {
  afterEach(cleanup);

  const trigger = <button>Open modal</button>;

  it("does not render a closed modal", () => {
    const onConfirm = vi.fn();

    render(
      <TooltipProvider>
        <ConfirmationModal
          onConfirm={onConfirm}
          trigger={trigger}
          title="Are you sure?"
        >
          Some extra information.
        </ConfirmationModal>
      </TooltipProvider>,
    );
    expect(screen.getByText("Open modal")).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeFalsy();
  });

  it("opens modal on clicking trigger", () => {
    const onConfirm = vi.fn();

    render(
      <TooltipProvider>
        <ConfirmationModal
          onConfirm={onConfirm}
          trigger={trigger}
          title="Are you sure?"
        >
          Some extra information.
        </ConfirmationModal>
      </TooltipProvider>,
    );

    fireEvent.click(screen.getByText("Open modal"));

    expect(screen.getByRole("dialog")).toMatchSnapshot();
  });

  it("calls onConfirm on confirmation", () => {
    const onConfirm = vi.fn();

    render(
      <TooltipProvider>
        <ConfirmationModal
          onConfirm={onConfirm}
          trigger={trigger}
          title="Are you sure?"
        >
          Some extra information.
        </ConfirmationModal>
      </TooltipProvider>,
    );

    fireEvent.click(screen.getByText("Open modal"));

    fireEvent.click(screen.getByText("Continue"));
    expect(onConfirm).toHaveBeenCalled();

    // dialog closed
    expect(screen.queryByRole("dialog")).toBeFalsy();
  });

  it("closes modal with Esc", () => {
    const onConfirm = vi.fn();

    render(
      <TooltipProvider>
        <ConfirmationModal
          onConfirm={onConfirm}
          trigger={trigger}
          title="Are you sure?"
        >
          Some extra information.
        </ConfirmationModal>
      </TooltipProvider>,
    );

    fireEvent.click(screen.getByText("Open modal"));

    fireEvent.keyDown(screen.getByRole("dialog"), {
      key: "Escape",
      code: "Escape",
      keyCode: 27,
    });

    // dialog closed
    expect(screen.queryByRole("dialog")).toBeFalsy();
  });
});
