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

import classNames from "classnames";
import { forwardRef } from "react";

import styles from "./EmptyState.module.css";

/**
 * A component to display a message when a list is empty
 */
export const EmptyState = forwardRef<
  HTMLDivElement,
  React.ComponentPropsWithoutRef<"div">
>(function EmptyState({ children, ...props }, ref) {
  const className = classNames(styles.emptyState, props.className);
  return (
    <div ref={ref} {...props} className={className}>
      {children}
    </div>
  );
});
