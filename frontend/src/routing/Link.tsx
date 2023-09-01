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

import styles from "./Link.module.css";
import { appConfigAtom, routeAtom } from "./atoms";
import { Route, routeToPath } from "./routes";

// Filter out clicks with modifiers or that have been prevented
const shouldHandleClick = (e: React.MouseEvent): boolean =>
  !e.defaultPrevented &&
  e.button === 0 &&
  !(e.metaKey || e.altKey || e.ctrlKey || e.shiftKey);

const Link: React.FC<
  {
    route: Route;
    // adds button-like styling to link element
    kind?: "button";
  } & React.HTMLProps<HTMLAnchorElement>
> = ({ route, children, kind, className, ...props }) => {
  const config = useAtomValue(appConfigAtom);
  const path = routeToPath(route);
  const fullUrl = config.root + path;
  const setRoute = useSetAtom(routeAtom);

  // TODO: we should probably have more user control over this
  const [isPending, startTransition] = useTransition();

  const classNames = [
    kind === "button" ? styles.linkButton : "",
    className,
  ].join("");

  return (
    <a
      href={fullUrl}
      onClick={(e: React.MouseEvent): void => {
        // Only handle left clicks without modifiers
        if (!shouldHandleClick(e)) {
          return;
        }

        e.preventDefault();
        startTransition(() => {
          setRoute(route);
        });
      }}
      className={classNames}
      {...props}
    >
      {isPending ? "Loading..." : children}
    </a>
  );
};

export default Link;
