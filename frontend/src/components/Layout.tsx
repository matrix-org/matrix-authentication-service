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

import { Link } from "@vector-im/compound-web";
import { useAtomValue } from "jotai";

import { currentUserIdAtom } from "../atoms";
import { isErr, unwrapErr, unwrapOk } from "../result";

import GraphQLError from "./GraphQLError";
import styles from "./Layout.module.css";
import NavBar from "./NavBar";
import NavItem from "./NavItem";
import NotLoggedIn from "./NotLoggedIn";
import UserGreeting from "./UserGreeting";

const Layout: React.FC<{ children?: React.ReactNode }> = ({ children }) => {
  const result = useAtomValue(currentUserIdAtom);
  if (isErr(result)) return <GraphQLError error={unwrapErr(result)} />;

  const userId = unwrapOk(result);
  if (userId === null)
    return (
      <div className={styles.container}>
        <NotLoggedIn />
      </div>
    );

  return (
    <div className={styles.container}>
      <UserGreeting userId={userId} />

      <NavBar>
        <NavItem route={{ type: "home" }}>Home</NavItem>
        <NavItem route={{ type: "email-list" }}>Emails</NavItem>
      </NavBar>

      <main>{children}</main>

      <footer className={styles.footer}>
        <nav className={styles.footerLinks}>
          <ul>
            <Link href="https://matrix.org/legal/copyright-notice">Info</Link>
            <Link href="https://matrix.org/legal/privacy-notice">Privacy</Link>
            <Link href="https://matrix.org/legal/terms-and-conditions">
              Terms & Conditions
            </Link>
          </ul>
        </nav>
      </footer>
    </div>
  );
};

export default Layout;
