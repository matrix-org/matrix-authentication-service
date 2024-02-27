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

import { ArgTypes, Decorator, Parameters, Preview } from "@storybook/react";
import { TooltipProvider } from "@vector-im/compound-web";
import { useLayoutEffect } from "react";

import "../src/main.css";
import i18n from "../src/i18n";

import localazyMetadata from "./locales";

export const parameters: Parameters = {
  actions: { argTypesRegex: "^on[A-Z].*" },
  controls: {
    matchers: {
      color: /(background|color)$/i,
      date: /Date$/,
    },
  },
};

export const globalTypes = {
  theme: {
    name: "Theme",
    defaultValue: "system",
    description: "Global theme for components",
    toolbar: {
      icon: "circlehollow",
      title: "Theme",
      items: [
        { title: "System", value: "system", icon: "browser" },
        { title: "Light", value: "light", icon: "sun" },
        { title: "Light (high contrast)", value: "light-hc", icon: "sun" },
        { title: "Dark", value: "dark", icon: "moon" },
        { title: "Dark (high contrast)", value: "dark-hc", icon: "moon" },
      ],
    },
  },
} satisfies ArgTypes;

const allThemesClasses = globalTypes.theme.toolbar.items.map(
  ({ value }) => `cpd-theme-${value}`,
);

const ThemeSwitcher: React.FC<{
  theme: string;
}> = ({ theme }) => {
  useLayoutEffect(() => {
    document.documentElement.classList.remove(...allThemesClasses);
    if (theme !== "system") {
      document.documentElement.classList.add(`cpd-theme-${theme}`);
    }
    return () => document.documentElement.classList.remove(...allThemesClasses);
  }, [theme]);

  return null;
};

const withThemeProvider: Decorator = (Story, context) => {
  return (
    <>
      <ThemeSwitcher theme={context.globals.theme} />
      <TooltipProvider>
        <Story />
      </TooltipProvider>
    </>
  );
};

export const decorators: Decorator[] = [withThemeProvider];

const locales = Object.fromEntries(
  localazyMetadata.languages.map(({ language, name, localizedName }) => [
    language,
    `${localizedName} (${name})`,
  ]),
);

const preview: Preview = {
  globals: {
    locale: localazyMetadata.baseLocale,
    locales,
  },
  parameters: {
    i18n,
  },
};

export default preview;
