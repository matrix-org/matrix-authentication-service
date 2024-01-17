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

import type { Meta, StoryObj } from "@storybook/react";

import Footer from "./Footer";

const meta = {
  title: "UI/Footer",
  component: Footer,
  tags: ["autodocs"],
} satisfies Meta<typeof Footer>;

export default meta;
type Story = StoryObj<typeof Footer>;

export const Basic: Story = {
  args: {
    tosUri: "https://matrix.org/legal/terms-and-conditions/",
    policyUri: "https://matrix.org/legal/privacy-notice/",
    imprint: "The Matrix.org Foundation C.I.C.",
  },
};

export const LinksOnly: Story = {
  args: {
    tosUri: "https://matrix.org/legal/terms-and-conditions/",
    policyUri: "https://matrix.org/legal/privacy-notice/",
  },
};

export const ImprintOnly: Story = {
  args: {
    imprint: "The Matrix.org Foundation C.I.C.",
  },
};

export const OneLink: Story = {
  args: {
    tosUri: "https://matrix.org/legal/terms-and-conditions/",
    imprint: "The Matrix.org Foundation C.I.C.",
  },
};
