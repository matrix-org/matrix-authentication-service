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
    <div className="bg-grey-25 text-black-900 dark:bg-black-800 dark:text-white flex flex-col min-h-screen">
      <NavBar className="mx-auto px-3 py-4 container">
        <NavItem to="/">Home</NavItem>
        <NavItem to="/dumb">Dumb</NavItem>
      </NavBar>

      <main className="mx-auto p-4 container">{children}</main>
    </div>
  );
};

export default Layout;
