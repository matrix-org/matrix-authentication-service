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
import {
  render,
  cleanup,
  screen,
  fireEvent,
  waitForElementToBeRemoved,
} from "@testing-library/react";
import { describe, it, expect, afterEach, vi } from "vitest";

import Meta, { Basic, MultipleSessions } from "./EndSessionButton.stories";

describe("<EndSessionButton />", () => {
  afterEach(cleanup);

  it("renders a basic end session button", () => {
    const Component = composeStory(Basic, Meta);
    const { container } = render(<Component />);

    expect(container).toMatchSnapshot();
  });

  it("renders an end session button for multiple sessions", () => {
    const Component = composeStory(MultipleSessions, Meta);
    render(<Component />);

    expect(screen.getByText("End 3 sessions")).toBeTruthy();
  });

  it("opens a confirmation modal on click", async () => {
    const Component = composeStory(Basic, Meta);
    render(<Component />);

    fireEvent.click(screen.getByText("End session"));

    await screen.findByRole("alertdialog");
    expect(
      screen.getByText("Are you sure you want to end this session?"),
    ).toBeTruthy();
  });

  it("does not end session when confirmation is cancelled", async () => {
    const endSession = vi.fn();
    const Component = composeStory(Basic, {
      ...Meta,
      args: {
        endSession,
      },
    });
    render(<Component />);

    fireEvent.click(screen.getByText("End session"));

    await screen.findByRole("alertdialog");

    fireEvent.click(screen.getByText("Cancel"));

    expect(endSession).not.toHaveBeenCalled();
    // no spinner
    expect(screen.queryByRole("status")).toBeFalsy();
  });

  it("ends session and displays loader when confirmation is confirmed", async () => {
    // store the resolve here so we can test pending state
    let completeEndSessionHandle!: () => void;
    const endSession = vi.fn().mockImplementation(async (): Promise<void> => {
      await new Promise<void>((resolve) => {
        completeEndSessionHandle = resolve;
      });
    });
    const Component = composeStory(Basic, {
      ...Meta,
      args: {
        endSession,
      },
    });
    render(<Component />);

    fireEvent.click(screen.getByText("End session"));

    await screen.findByRole("alertdialog");

    fireEvent.click(screen.getByText("Continue"));

    // loading
    expect(screen.queryByRole("status")).toBeTruthy();
    expect(endSession).toHaveBeenCalled();

    // complete the mocked end session
    completeEndSessionHandle();

    // no more loader
    await waitForElementToBeRemoved(() => screen.queryByRole("status"));
  });
});
