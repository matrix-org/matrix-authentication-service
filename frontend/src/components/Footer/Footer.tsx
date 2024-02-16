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
import { Translation } from "react-i18next";

import styles from "./Footer.module.css";

type Props = {
  policyUri?: string;
  tosUri?: string;
  imprint?: string;
  dontSuspend?: boolean;
};

const Footer: React.FC<Props> = ({
  policyUri,
  tosUri,
  imprint,
  dontSuspend,
}) => (
  <Translation useSuspense={!dontSuspend}>
    {(t) => (
      <footer className={styles.legalFooter}>
        {(policyUri || tosUri) && (
          <nav>
            {policyUri && (
              <Link
                href={policyUri}
                title={t("branding.privacy_policy.alt", {
                  defaultValue: "Link to the service privacy policy",
                })}
              >
                {t("branding.privacy_policy.link", {
                  defaultValue: "Privacy policy",
                })}
              </Link>
            )}

            {policyUri && tosUri && (
              <div className={styles.separator} aria-hidden="true">
                •
              </div>
            )}

            {tosUri && (
              <Link
                href={tosUri}
                title={t("branding.terms_and_conditions.alt", {
                  defaultValue: "Link to the service terms and conditions",
                })}
              >
                {t("branding.terms_and_conditions.link", {
                  defaultValue: "Terms and conditions",
                })}
              </Link>
            )}
          </nav>
        )}

        {imprint && <p className={styles.imprint}>{imprint}</p>}
      </footer>
    )}
  </Translation>
);

export default Footer;
