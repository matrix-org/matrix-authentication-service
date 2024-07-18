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

import { createLink } from "@tanstack/react-router";
import CloseIcon from "@vector-im/compound-design-tokens/assets/web/icons/close";
import classNames from "classnames";
import { forwardRef } from "react";

import styles from "./Filter.module.css";

type Props = React.ComponentPropsWithRef<"a"> & {
  enabled?: boolean;
};

/**
 * A link which looks like a chip used when filtering items
 */
export const Filter = createLink(
  forwardRef<HTMLAnchorElement, Props>(function Filter(
    { children, enabled, ...props },
    ref,
  ) {
    const className = classNames(
      styles.filter,
      enabled ? styles.enabledFilter : styles.disabledFilter,
      props.className,
    );

    return (
      <a {...props} ref={ref} className={className}>
        {children}
        {enabled && <CloseIcon className={styles.closeIcon} />}
      </a>
    );
  }),
);
