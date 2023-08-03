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

import { Link as CpdLink } from "@vector-im/compound-web";
import { useAtomValue } from "jotai";

import { Link, Route, routeAtom } from "../Router";

import styles from "./NavItem.module.css";

const NavItem: React.FC<React.PropsWithChildren<{ route: Route }>> = ({
  route,
  children,
}) => {
  const currentRoute = useAtomValue(routeAtom);
  return (
    <li>
      <Link
        className={styles.navItem}
        route={route}
        aria-current={currentRoute.type === route.type ? "page" : undefined}
      >
        {children}
      </Link>
    </li>
  );
};

export const ExternalLink: React.FC<
  React.PropsWithChildren<{ href: string }>
> = ({ href, children }) => (
  <li>
    <CpdLink href={href}>{children}</CpdLink>
  </li>
);

export default NavItem;
