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

import styles from "./Layout.module.css";
import NavBar from "./NavBar";
import NavItem, { ExternalLink } from "./NavItem";

const Separator: React.FC = () => <hr className={styles.separator} />;

const Layout: React.FC<{ children?: React.ReactNode }> = ({ children }) => {
  return (
    <div className={styles.container}>
      <NavBar>
        <NavItem route={{ type: "home" }}>Sessions</NavItem>
        <NavItem route={{ type: "account" }}>Emails</NavItem>
      </NavBar>

      <Separator />

      <main>{children}</main>

      <Separator />

      <footer className={styles.footer}>
        <a href="https://matrix.org" target="_blank" rel="noreferrer noopener">
          <img
            className="inline my-2"
            height={32}
            width={75}
            src="https://matrix.org/images/matrix-logo.svg"
            alt="Matrix.org"
          />
        </a>

        <NavBar>
          <ExternalLink href="https://matrix.org/legal/copyright-notice">
            Info
          </ExternalLink>
          <ExternalLink href="https://matrix.org/legal/privacy-notice">
            Privacy
          </ExternalLink>
          <ExternalLink href="https://matrix.org/legal/terms-and-conditions">
            Terms & Conditions
          </ExternalLink>
        </NavBar>
      </footer>
    </div>
  );
};

export default Layout;
