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

import { Provider } from "jotai";
import { useHydrateAtoms } from "jotai/utils";

import { appConfigAtom, locationAtom } from "../routing";

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

/**
 * Utility for testing components that rely on routing or location
 * For example any component that includes a <Link />
 * Eg:
 * ```
 * const component = create(
      <WithLocation path="/">
        <NavItem route={{ type: "profile" }}>Active</NavItem>
      </WithLocation>,
    );
 * ```
 */
export const WithLocation: React.FC<
  React.PropsWithChildren<{ path?: string }>
> = ({ children, path }) => {
  return (
    <Provider>
      <HydrateLocation path={path || "/"}>{children}</HydrateLocation>
    </Provider>
  );
};
