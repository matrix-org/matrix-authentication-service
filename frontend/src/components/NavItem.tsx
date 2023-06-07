// Copyright 2022 The Matrix.org Foundation C.I.C.
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

import { useAtomValue } from "jotai";

import { Link, Route, routeAtom } from "../Router";

type NavItemProps = {
  children: React.ReactNode;
} & ({ route: Route; href?: never } | { route?: never; href: string });

function isRoute(route: Route | undefined): route is Route {
  return !!route?.type;
}

function isHref(href: string | undefined): href is string {
  return typeof href === "string";
}

const NavItem: React.FC<NavItemProps> = ({ route, href, children }) => {
  const currentRoute = useAtomValue(routeAtom);
  return (
    <li className="m-1 mr-0">
      {isRoute(route) && (
        <Link
          route={route}
          className={currentRoute.type === route.type ? "active" : ""}
        >
          {children}
        </Link>
      )}
      {isHref(href) && (
        <a href={href} target="_blank" rel="noopenner noreferrer">
          {children}
        </a>
      )}
    </li>
  );
};

export default NavItem;
