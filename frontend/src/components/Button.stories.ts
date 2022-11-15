import type { Meta, StoryObj } from "@storybook/react";

import Button from "./Button";

const meta: Meta<typeof Button> = {
  title: "UI/Button",
  component: Button,
  tags: ["docsPage"],
  argTypes: {
    onClick: { action: true },
    compact: {
      defaultValue: false,
    },
    ghost: {
      defaultValue: false,
    },
    disabled: {
      defaultValue: false,
    },
  },
};

export default meta;
type Story = StoryObj<typeof Button>;

export const Basic: Story = {
  args: {
    children: "Button",
  },
};

export const Regular: Story = {
  args: {
    children: "Button",
    compact: false,
    ghost: false,
    disabled: false,
  },
};

export const Compact: Story = {
  args: {
    children: "Compact",
    compact: true,
    ghost: false,
    disabled: false,
  },
};

export const Disabled: Story = {
  args: {
    children: "Disabled",
    compact: false,
    ghost: false,
    disabled: true,
  },
};

export const Ghost: Story = {
  args: {
    children: "Ghost",
    compact: false,
    ghost: true,
    disabled: false,
  },
};

export const GhostDisabled: Story = {
  args: {
    children: "Ghost",
    compact: false,
    ghost: true,
    disabled: true,
  },
};
