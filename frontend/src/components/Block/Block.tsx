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

import { Heading } from "@vector-im/compound-web";
import cx from "classnames";
import { ReactNode } from "react";

import styles from "./Block.module.css";

type Props = React.PropsWithChildren<{
  title?: ReactNode;
  className?: string;
  highlight?: boolean;
}>;

const Block: React.FC<Props> = ({ children, className, highlight, title }) => {
  return (
    <div className={cx(styles.block, className)} data-active={highlight}>
      {title && (
        <Heading as="h4" size="sm" weight="semibold" className={styles.title}>
          {title}
        </Heading>
      )}

      {children}
    </div>
  );
};

export default Block;
