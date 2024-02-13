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
import cx from "classnames";
import { forwardRef } from "react";

import styles from "./Link.module.css";

export const NewLink: LinkComponent = forwardRef<
  HTMLAnchorElement,
  Parameters<typeof useLinkProps>[0]
>(({ children, ...props }, ref) => {
  const { className, ...newProps } = useLinkProps(props);

  return (
    <CompoundLink
      kind="primary"
      ref={ref}
      className={cx(className, styles.linkButton)}
      children={children}
      {...newProps}
    />
  );
}) as LinkComponent;
