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

import NavBar from "./NavBar";
import NavItem from "./NavItem";

const Layout: React.FC<{ children?: React.ReactNode }> = ({ children }) => {
  return (
    <>
      <NavBar className="nav-bar container">
        <NavItem route={{ type: "home" }}>Home</NavItem>
        <NavItem route={{ type: "account" }}>My Account</NavItem>
      </NavBar>

      <hr className="my-2" />

      <main className="container">{children}</main>

      <hr className="my-2" />

      <footer className="text-center">
        <a href="https://matrix.org" target="_blank" rel="noreferrer noopener">
          <img
            className="inline my-2"
            src="https://matrix.org/images/matrix-logo.svg"
            alt="Matrix.org"
          />
        </a>

        <NavBar className="nav-bar container">
          <NavItem href="https://matrix.org/legal/copyright-notice">
            Info
          </NavItem>
          <NavItem href="https://matrix.org/legal/privacy-notice">
            Privacy
          </NavItem>
          <NavItem href="https://matrix.org/legal/terms-and-conditions">
            Terms & Conditions
          </NavItem>
        </NavBar>
      </footer>
    </>
  );
};

export default Layout;
