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

import Typography from "./Typography";

const meta: Meta<typeof Typography> = {
  title: "UI/Typography",
  component: Typography,
  tags: ["docsPage"],
  args: {
    children: "Typography",
  },
};

export default meta;
type Story = StoryObj<typeof Typography>;

export const Basic: Story = {
  args: {
    children: "Hello",
    variant: "body",
  },
};

export const Headline: Story = {
  args: {
    children: "Headline",
    variant: "headline",
  },
};

export const Title: Story = {
  args: {
    children: "Title",
    variant: "title",
  },
};

export const Subtitle: Story = {
  args: {
    children: "Subtitle",
    variant: "subtitle",
  },
};

export const SubtitleSemiBold: Story = {
  args: {
    children: "Subtitle Semi Bold",
    variant: "subtitle",
    bold: true,
  },
};

export const Body: Story = {
  args: {
    children: "Body",
    variant: "body",
  },
};

export const BodySemiBold: Story = {
  args: {
    children: "Body",
    variant: "body",
    bold: true,
  },
};

export const Caption: Story = {
  args: {
    children: "Caption",
    variant: "caption",
  },
};

export const CaptionSemiBold: Story = {
  args: {
    children: "Caption",
    variant: "caption",
    bold: true,
  },
};

export const Micro: Story = {
  args: {
    children: "Micro",
    variant: "caption",
  },
};

export const MicroSemiBold: Story = {
  args: {
    children: "Micro",
    variant: "caption",
    bold: true,
  },
};
