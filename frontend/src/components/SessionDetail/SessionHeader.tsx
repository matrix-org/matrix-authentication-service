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

import { Link } from "@tanstack/react-router";
import IconArrowLeft from "@vector-im/compound-design-tokens/icons/arrow-left.svg?react";
import { H3 } from "@vector-im/compound-web";

import styles from "./SessionHeader.module.css";

const SessionHeader: React.FC<React.ComponentProps<typeof Link>> = ({
  children,
  ...rest
}) => {
  return (
    <header className={styles.header}>
      <Link className={styles.backButton} {...rest}>
        <IconArrowLeft />
      </Link>
      <H3>{children}</H3>
    </header>
  );
};

export default SessionHeader;
