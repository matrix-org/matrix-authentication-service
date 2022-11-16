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

module.exports = {
  stories: ["../src/**/*.stories.mdx", "../src/**/*.stories.@(js|jsx|ts|tsx)"],
  addons: [
    // Automatic docs pages
    "@storybook/addon-docs",

    // Controls of components props
    "@storybook/addon-controls",

    // Document components actions
    "@storybook/addon-actions",

    // Helps measuring elements
    "@storybook/addon-measure",

    // Helps showing components boundaries
    "@storybook/addon-outline",

    // Quickly change viewport size
    "@storybook/addon-viewport",

    // Theme switch toolbar
    "@storybook/addon-toolbars",
  ],
  framework: {
    name: "@storybook/react-vite",
    options: {},
  },
  typescript: {
    reactDocgen: "react-docgen-typescript",
  },
  core: {
    disableTelemetry: true,
  },
  docs: {
    docsPage: true,
  },
};
