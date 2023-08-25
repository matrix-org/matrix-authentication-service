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

import { appConfigAtom, locationAtom } from "../../Router";
import { makeFragmentData } from "../../gql";
import { FRAGMENT as EMAIL_FRAGMENT } from "../UserEmail";

import UserHome, { FRAGMENT } from "./UserHome";

type Props = {
  primaryEmail: string | null;
  unverifiedEmails: number;
  confirmedEmails: number;
  oauth2Sessions: number;
  browserSessions: number;
  compatSessions: number;
};

const WithHomePage: React.FC<React.PropsWithChildren<{}>> = ({ children }) => {
  useHydrateAtoms([
    [appConfigAtom, { root: "/" }],
    [locationAtom, { pathname: "/" }],
  ]);
  return <>{children}</>;
};

const Template: React.FC<Props> = ({
  primaryEmail: email,
  unverifiedEmails,
  confirmedEmails,
  oauth2Sessions,
  browserSessions,
  compatSessions,
}) => {
  let primaryEmail = null;
  if (email) {
    primaryEmail = {
      id: "email:123",
      ...makeFragmentData(
        {
          id: "email:123",
          email,
          confirmedAt: new Date(),
        },
        EMAIL_FRAGMENT,
      ),
    };
  }
  const data = makeFragmentData(
    {
      id: "user:123",
      primaryEmail,
      unverifiedEmails: {
        totalCount: unverifiedEmails,
      },
      confirmedEmails: {
        totalCount: confirmedEmails,
      },
      oauth2Sessions: {
        totalCount: oauth2Sessions,
      },
      browserSessions: {
        totalCount: browserSessions,
      },
      compatSessions: {
        totalCount: compatSessions,
      },
    },
    FRAGMENT,
  );
  return (
    <Provider>
      <WithHomePage>
        <UserHome user={data} />
      </WithHomePage>
    </Provider>
  );
};

const meta = {
  title: "Pages/User Home",
  component: Template,
  tags: ["autodocs"],
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

export const Basic: Story = {
  args: {
    primaryEmail: "hello@example.com",
    unverifiedEmails: 0,
    confirmedEmails: 5,
    oauth2Sessions: 3,
    compatSessions: 1,
    browserSessions: 2,
  },
};

export const Empty: Story = {
  args: {
    primaryEmail: "hello@example.com",
    unverifiedEmails: 0,
    confirmedEmails: 1,
    oauth2Sessions: 0,
    compatSessions: 0,
    browserSessions: 0,
  },
};

export const UnverifiedEmails: Story = {
  args: {
    primaryEmail: "hello@example.com",
    unverifiedEmails: 1,
    confirmedEmails: 1,
    oauth2Sessions: 0,
    compatSessions: 0,
    browserSessions: 0,
  },
};
