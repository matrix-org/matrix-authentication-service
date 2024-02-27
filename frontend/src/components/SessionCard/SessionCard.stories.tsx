// Copyright 2024 The Matrix.org Foundation C.I.C.
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
import IconSignOut from "@vector-im/compound-design-tokens/icons/sign-out.svg?react";
import { Button } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import { DeviceType } from "../../gql/graphql";

import * as Card from "./SessionCard";

const Template: React.FC<{
  deviceType: DeviceType;
  deviceName: string;
  clientName?: string;
  disabled?: boolean;
}> = ({ deviceType, deviceName, clientName, disabled }) => {
  const { t } = useTranslation();
  return (
    <Card.Root>
      <Card.Body disabled={disabled}>
        <Card.Header type={deviceType}>
          <Card.Name name={deviceName} />
          {clientName && <Card.Client name={clientName} />}
        </Card.Header>
        <Card.Metadata>
          <Card.Info label="Last active">2 hours ago</Card.Info>
          <Card.Info label="Signed in">NOV 30, 2023</Card.Info>
          <Card.Info label="Device ID">XXXXXX</Card.Info>
        </Card.Metadata>
      </Card.Body>
      {!disabled && (
        <Card.Action>
          <Button kind="secondary" destructive size="sm" Icon={IconSignOut}>
            {t("frontend.end_session_button.text")}
          </Button>
        </Card.Action>
      )}
    </Card.Root>
  );
};

const meta = {
  title: "UI/Session/Card",
  component: Template,
  args: {
    disabled: false,
    deviceName: "MacBook Pro 16",
    clientName: "Firefox",
    deviceType: DeviceType.Pc,
  },
  argTypes: {
    deviceType: { control: "select", options: Object.values(DeviceType) },
    disabled: { control: "boolean" },
    deviceName: { control: "text" },
    clientName: { control: "text" },
  },
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

export const Basic: Story = {};
