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

import type { IWindow } from "happy-dom";
import { Provider } from "jotai";
import { useHydrateAtoms } from "jotai/utils";
import { create } from "react-test-renderer";
import { beforeEach, describe, expect, it } from "vitest";

import { appConfigAtom, locationAtom } from "../../Router";

import NavItem from "./NavItem";

beforeEach(async () => {
  const w = window as unknown as IWindow;

  // For some reason, the locationAtom gets updated with `about:black` on render,
  // so we need to set a "real" location and wait for the next tick
  w.happyDOM.setURL("https://example.com/");
  await w.happyDOM.whenAsyncComplete();
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
      <HydrateLocation path={path}>{children}</HydrateLocation>
    </Provider>
  );
};

describe("NavItem", () => {
  it("render an active <NavItem />", () => {
    const component = create(
      <WithLocation path="/">
        <NavItem route={{ type: "home" }}>Active</NavItem>
      </WithLocation>,
    );
    const tree = component.toJSON();
    expect(tree).toMatchSnapshot();
  });

  it("render an inactive <NavItem />", () => {
    const component = create(
      <WithLocation path="/account">
        <NavItem route={{ type: "home" }}>Inactive</NavItem>
      </WithLocation>,
    );
    const tree = component.toJSON();
    expect(tree).toMatchSnapshot();
  });

  it("renders a different route", () => {
    const component = create(
      <WithLocation path="/">
        <NavItem route={{ type: "profile" }}>Emails</NavItem>
      </WithLocation>,
    );
    const tree = component.toJSON();
    expect(tree).toMatchSnapshot();
  });
});
