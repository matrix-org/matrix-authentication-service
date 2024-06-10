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

import { Link } from "@tanstack/react-router";
import { Form } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import styles from "./AccountManagementPasswordPreview.module.css";

export default function AccountManagementPasswordPreview(): React.ReactElement {
  const { t } = useTranslation();

  return (
    <Form.Root>
      <Form.Field name="password_preview">
        <Form.Label>{t("frontend.account.password.label")}</Form.Label>

        <div className="flex items-center gap-2">
          <Form.TextControl
            type="password"
            readOnly
            value="this looks like a password"
            className={styles.passwordPreviewField}
          />
        </div>

        <Form.HelpMessage>
          <Link to="/password/change" className={styles.link}>
            {t("frontend.account.password.change")}
          </Link>
        </Form.HelpMessage>
      </Form.Field>
    </Form.Root>
  );
}
