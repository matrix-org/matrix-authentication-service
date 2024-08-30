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

import * as Collapsible from "@radix-ui/react-collapsible";
import IconChevronUp from "@vector-im/compound-design-tokens/assets/web/icons/chevron-up";
import classNames from "classnames";

import styles from "./Collapsible.module.css";

export const Trigger: React.FC<
  React.ComponentProps<typeof Collapsible.Trigger>
> = ({ children, className, ...props }) => {
  return (
    <Collapsible.Trigger
      {...props}
      className={classNames(styles.trigger, className)}
    >
      <div className={styles.triggerTitle}>{children}</div>
      <IconChevronUp
        className={styles.triggerIcon}
        height="24px"
        width="24px"
      />
    </Collapsible.Trigger>
  );
};

export const Content: React.FC<
  React.ComponentProps<typeof Collapsible.Content>
> = ({ className, ...props }) => {
  return (
    <Collapsible.Content
      {...props}
      className={classNames(styles.content, className)}
    />
  );
};

export const Root = Collapsible.Root;
