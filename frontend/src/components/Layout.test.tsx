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

import { render } from "@testing-library/react";
import { Provider } from "jotai";
import { useHydrateAtoms } from "jotai/utils";
import { Suspense } from "react";
import { describe, expect, it, vi, afterAll, beforeEach } from "vitest";

import { appConfigAtom, locationAtom } from "../Router";
import { currentUserIdAtom, GqlResult } from "../atoms";

import Layout from "./Layout";

beforeEach(async () => {
  // For some reason, the locationAtom gets updated with `about:black` on render,
  // so we need to set a "real" location and wait for the next tick
  window.location.assign("https://example.com/");
  // Wait the next tick for the location to update
  await new Promise((resolve) => setTimeout(resolve, 0));
});

const HydrateLocation: React.FC<React.PropsWithChildren<{ path: string }>> = ({
  children,
  path,
}) => {
  useHydrateAtoms([
    [appConfigAtom, { root: "/" }],
    [locationAtom, { pathname: path }],
  ]);
  return <>{children}</>;
};

const WithLocation: React.FC<React.PropsWithChildren<{ path: string }>> = ({
  children,
  path,
}) => {
  return (
    <Provider>
      <Suspense>
        <HydrateLocation path={path}>{children}</HydrateLocation>
      </Suspense>
    </Provider>
  );
};

describe("<Layout />", () => {
  beforeEach(() => {
    vi.spyOn(currentUserIdAtom, "read").mockResolvedValue(
      "abc123" as unknown as GqlResult<string | null>,
    );
  });
  afterAll(() => {
    vi.restoreAllMocks();
  });
  it("renders app navigation correctly", async () => {
    const component = render(
      <WithLocation path="/account">
        <Layout />
      </WithLocation>,
    );

    expect(await component.findByText("Profile")).toMatchSnapshot();
    expect(await component.findByText("Home")).toMatchSnapshot();
  });
});
