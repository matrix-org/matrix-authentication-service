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

import { createElement, Children } from "react";

type Variant = "headline" | "title" | "subtitle" | "body" | "caption" | "micro";

type Props = {
  children: React.ReactNode;
  variant: Variant;
  bold?: boolean;
};

const elementMap: Record<Variant, "h1" | "h2" | "h3" | "p" | "small"> = {
  headline: "h1",
  title: "h2",
  subtitle: "h3",
  body: "p",
  caption: "p",
  micro: "small",
};

const classMap: Record<Variant, string> = {
  headline: "text-3xl font-semibold",
  title: "text-2xl font-semibold",
  subtitle: "text-lg",
  body: "text-base",
  caption: "text-sm",
  micro: "text-xs",
};

const Typography: React.FC<Props> = ({ variant, children, bold }) => {
  const element = elementMap[variant];
  const boldClass = bold ? "font-semibold" : "";
  const className = `text-black dark:text-white ${boldClass} ${classMap[variant]}`;
  return createElement(element, { className }, ...Children.toArray(children));
};

export const Bold: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <em className="font-semibold">{children}</em>
);

export const Code: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <code className="font-mono text-sm">{children}</code>
);

export default Typography;
