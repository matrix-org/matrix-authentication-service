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

import {
  UseLinkPropsOptions,
  createLink,
  useLinkProps,
} from "@tanstack/react-router";
import { Button } from "@vector-im/compound-web";
import { forwardRef } from "react";

type Props = {
  kind?: "primary" | "secondary" | "tertiary";
  size?: "sm" | "lg";
  Icon?: React.ComponentType<React.SVGAttributes<SVGElement>>;
  destructive?: boolean;
};

// XXX: createLink is broken, so we work around it by using useLinkProps directly
export const ButtonLink = forwardRef<
  HTMLAnchorElement,
  Props & UseLinkPropsOptions
>(({ children, ...props }, ref) => {
  const linkProps = useLinkProps(props);
  return (
    <Button as="a" {...linkProps} ref={ref}>
      {children}
    </Button>
  );
}) as ReturnType<typeof createLink<typeof Button>>;
