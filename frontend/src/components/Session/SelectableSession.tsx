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

import { Checkbox } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import styles from "./SelectableSession.module.css";

type Props = {
  isSelected?: boolean;
  onSelect: () => void;
};

/**
 * Wrapper to add a controlled checkbox to a session tile
 */
const SelectableSession: React.FC<React.PropsWithChildren<Props>> = ({
  isSelected,
  onSelect,
  children,
}) => {
  const { t } = useTranslation();
  return (
    <div className={styles.selectableSession}>
      <Checkbox
        className={styles.checkbox}
        kind="primary"
        onChange={onSelect}
        aria-label={t("frontend.selectable_session.label")}
        checked={isSelected}
      />
      {children}
    </div>
  );
};

export default SelectableSession;
