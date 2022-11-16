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

import { NavLink, To } from "react-router-dom";

const NavItem: React.FC<{ to: To; children: React.ReactNode }> = ({
  to,
  children,
}) => (
  <li className="m-1 mr-0">
    <NavLink
      to={to}
      className={({ isActive }) =>
        (isActive
          ? "bg-accent text-white"
          : "hover:bg-grey-100 dark:hover:bg-grey-450 opacity-80 hover:opacity-100") +
        " p-2 rounded block uppercase font-medium"
      }
    >
      {children}
    </NavLink>
  </li>
);

export default NavItem;
