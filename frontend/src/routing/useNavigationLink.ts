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

import { useAtomValue, useSetAtom } from "jotai";
import { useTransition } from "react";

import { appConfigAtom, routeAtom } from "./atoms";
import { Route, routeToPath } from "./routes";

// Filter out clicks with modifiers or that have been prevented
const shouldHandleClick = (e: React.MouseEvent): boolean =>
  !e.defaultPrevented &&
  e.button === 0 &&
  !(e.metaKey || e.altKey || e.ctrlKey || e.shiftKey);

/**
 * A hook which controls a navigation link to a given route
 */
export const useNavigationLink = (
  route: Route,
): {
  onClick: (event: React.MouseEvent) => void;
  href: string;
  pending: boolean;
} => {
  const config = useAtomValue(appConfigAtom);
  const path = routeToPath(route);
  const href = config.root + path;
  const setRoute = useSetAtom(routeAtom);
  const [pending, startTransition] = useTransition();

  const onClick = (e: React.MouseEvent): void => {
    // Only handle left clicks without modifiers
    if (!shouldHandleClick(e)) {
      return;
    }

    e.preventDefault();
    startTransition(() => {
      setRoute(route);
    });
  };

  return { onClick, href, pending };
};
