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

import type { Meta, StoryObj } from "@storybook/react";
import { Provider } from "jotai";
import { useHydrateAtoms } from "jotai/utils";

import { appConfigAtom, locationAtom } from "../../routing";
import NavItem, { ExternalLink } from "../NavItem";

import NavBar from "./NavBar";

const meta = {
  title: "UI/Nav Bar",
  component: NavBar,
  tags: ["autodocs"],
  render: (props): React.ReactElement => (
    <Provider>
      <WithHomePage>
        <NavBar {...props}>
          <NavItem route={{ type: "sessions-overview" }}>Sessions</NavItem>
          <NavItem route={{ type: "profile" }}>Profile</NavItem>
          <ExternalLink href="https://example.com">External</ExternalLink>
        </NavBar>
      </WithHomePage>
    </Provider>
  ),
} satisfies Meta<typeof NavBar>;

const WithHomePage: React.FC<React.PropsWithChildren<{}>> = ({ children }) => {
  useHydrateAtoms([
    [appConfigAtom, { root: "/" }],
    [locationAtom, { pathname: "/" }],
  ]);
  return <>{children}</>;
};

export default meta;
type Story = StoryObj<typeof NavBar>;

export const Basic: Story = {};
