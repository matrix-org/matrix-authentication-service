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

import { Submit } from "@radix-ui/react-form";
import IconCheck from "@vector-im/compound-design-tokens/icons/check.svg?react";
import IconClose from "@vector-im/compound-design-tokens/icons/close.svg?react";
import { Tooltip } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import styles from "./EditInPlace.module.css";

// TODO: move this to compound
const EditInPlace: React.FC = () => {
  const { t } = useTranslation();

  return (
    <div className={styles.container}>
      <Tooltip label={t("action.save")}>
        <Submit className={styles.save}>
          <IconCheck />
        </Submit>
      </Tooltip>

      <Tooltip label={t("action.cancel")}>
        <button type="reset" className={styles.cancel}>
          <IconClose />
        </button>
      </Tooltip>
    </div>
  );
};

export default EditInPlace;
