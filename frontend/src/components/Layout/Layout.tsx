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

import { useAtomValue } from "jotai";
import { useTranslation } from "react-i18next";

import { appConfigAtom } from "../../routing";
import Footer from "../Footer";
import NavBar from "../NavBar";
import NavItem from "../NavItem";
import UserGreeting from "../UserGreeting";

import styles from "./Layout.module.css";

const Layout: React.FC<{
  user: React.ComponentProps<typeof UserGreeting>["user"];
  children?: React.ReactNode;
}> = ({ user, children }) => {
  const appConfig = useAtomValue(appConfigAtom);
  const { t } = useTranslation();

  return (
    <div className={styles.layoutContainer}>
      <UserGreeting user={user} />

      <NavBar>
        <NavItem to="/">{t("frontend.nav.profile")}</NavItem>
        <NavItem to="/sessions">{t("frontend.nav.sessions")}</NavItem>
      </NavBar>

      {children}

      <Footer
        imprint={appConfig.branding?.imprint}
        tosUri={appConfig.branding?.tosUri}
        policyUri={appConfig.branding?.policyUri}
      />
    </div>
  );
};

export default Layout;
