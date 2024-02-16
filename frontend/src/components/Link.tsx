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

import { LinkComponent, useLinkProps } from "@tanstack/react-router";
import { Link as CompoundLink } from "@vector-im/compound-web";
import { forwardRef } from "react";

type Props = {
  kind?: "primary" | "critical";
};

export const Link: LinkComponent<Props> = forwardRef<
  HTMLAnchorElement,
  Parameters<typeof useLinkProps>[0] & Props
>(({ children, kind, ...props }, ref) => {
  const linkProps = useLinkProps(props);

  return (
    <CompoundLink kind={kind} ref={ref} {...linkProps}>
      {children}
    </CompoundLink>
  );
}) as LinkComponent<Props>;
