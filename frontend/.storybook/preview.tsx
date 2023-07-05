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

import { ArgTypes, Decorator, Parameters } from "@storybook/react";
import { useLayoutEffect } from "react";
import "../src/main.css";

export const parameters: Parameters = {
  actions: { argTypesRegex: "^on[A-Z].*" },
  controls: {
    matchers: {
      color: /(background|color)$/i,
      date: /Date$/,
    },
  },
};

export const globalTypes: ArgTypes = {
  theme: {
    name: "Theme",
    description: "Global theme for components",
    defaultValue: "light",
    toolbar: {
      icon: "circlehollow",
      title: "Theme",
      items: [
        {
          title: "Light",
          value: "light",
          icon: "sun",
        },
        {
          title: "Dark",
          value: "dark",
          icon: "moon",
        },
      ],
    },
  },
};

const ThemeSwitcher: React.FC<{ theme?: "light" | "dark" }> = ({ theme }) => {
  useLayoutEffect(() => {
    if (theme === "dark") {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }

    return () => document.documentElement.classList.remove("dark");
  }, [theme]);

  return null;
};

const withThemeProvider: Decorator = (Story, context) => {
  return (
    <>
      <ThemeSwitcher theme={context.globals.theme} />
      <Story />
    </>
  );
};

export const decorators: Decorator[] = [withThemeProvider];
