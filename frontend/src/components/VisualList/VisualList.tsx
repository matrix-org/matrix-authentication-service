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

import { Text } from "@vector-im/compound-web";
import {
  FC,
  ForwardRefExoticComponent,
  ReactNode,
  RefAttributes,
  SVGProps,
} from "react";

import styles from "./VisualList.module.css";

type Props = {
  children: ReactNode;
};

export const VisualListItem: FC<{
  Icon: ForwardRefExoticComponent<
    Omit<SVGProps<SVGSVGElement>, "ref" | "children"> &
      RefAttributes<SVGSVGElement>
  >;
  iconColor?: string;
  label: string;
}> = ({ Icon, iconColor, label }) => {
  return (
    <li className={styles.scope}>
      <Icon color={iconColor ?? "var(--cpd-color-icon-tertiary)"} />
      <Text size="md" weight="medium">
        {label}
      </Text>
    </li>
  );
};

export const VisualList: React.FC<Props> = ({ children }) => {
  return <ul className={styles.scopeList}>{children}</ul>;
};
