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

import styles from "./Link.module.css";
import { Route } from "./routes";
import { useNavigationLink } from "./useNavigationLink";

const Link: React.FC<
  {
    route: Route;
    // adds button-like styling to link element
    kind?: "button";
  } & React.HTMLProps<HTMLAnchorElement>
> = ({ route, children, kind, className, ...props }) => {
  const { onClick, href, pending } = useNavigationLink(route);

  const classNames = [
    kind === "button" ? styles.linkButton : "",
    className,
  ].join("");

  return (
    <a href={href} onClick={onClick} className={classNames} {...props}>
      {pending ? "Loading..." : children}
    </a>
  );
};

export default Link;
