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

import { Link } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import styles from "./Footer.module.css";

type Props = {
  policyUri?: string;
  tosUri?: string;
  imprint?: string;
};

const Footer: React.FC<Props> = ({ policyUri, tosUri, imprint }) => {
  const { t } = useTranslation();
  return (
    <footer className={styles.legalFooter}>
      {(policyUri || tosUri) && (
        <nav>
          {policyUri && (
            <Link href={policyUri} title={t("branding.privacy_policy.alt")}>
              {t("branding.privacy_policy.link")}
            </Link>
          )}

          {policyUri && tosUri && (
            <div className={styles.separator} aria-hidden="true">
              •
            </div>
          )}

          {tosUri && (
            <Link href={tosUri} title={t("branding.terms_and_conditions.alt")}>
              {t("branding.terms_and_conditions.link")}
            </Link>
          )}
        </nav>
      )}

      {imprint && <p className={styles.imprint}>{imprint}</p>}
    </footer>
  );
};

export default Footer;
