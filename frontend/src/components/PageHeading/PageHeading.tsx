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

import cx from "classnames";

import styles from "./PageHeading.module.css";

type Props = {
  Icon: React.ComponentType<React.SVGAttributes<SVGElement>>;
  invalid?: boolean;
  success?: boolean;
  title: string;
  subtitle?: string;
};

const PageHeading: React.FC<Props> = ({
  Icon,
  invalid,
  success,
  title,
  subtitle,
}) => (
  <header className={styles.pageHeading}>
    <div
      className={cx(
        styles.icon,
        invalid && styles.invalid,
        success && styles.success,
      )}
    >
      <Icon />
    </div>

    <div className={styles.header}>
      <h1 className={styles.title}>{title}</h1>
      {subtitle && <p className={styles.text}>{subtitle}</p>}
    </div>
  </header>
);

export default PageHeading;
