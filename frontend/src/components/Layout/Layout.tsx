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

import { currentUserIdAtom } from "../../atoms";
import { isErr, unwrapErr, unwrapOk } from "../../result";
import { appConfigAtom, routeAtom } from "../../routing";
import Footer from "../Footer";
import GraphQLError from "../GraphQLError";
import NavBar from "../NavBar";
import NavItem from "../NavItem";
import NotLoggedIn from "../NotLoggedIn";
import UserGreeting from "../UserGreeting";

import styles from "./Layout.module.css";

const Layout: React.FC<{ children?: React.ReactNode }> = ({ children }) => {
  const route = useAtomValue(routeAtom);
  const appConfig = useAtomValue(appConfigAtom);
  const result = useAtomValue(currentUserIdAtom);
  const { t } = useTranslation();

  if (isErr(result)) return <GraphQLError error={unwrapErr(result)} />;

  // Hide the nav bar & user greeting on the verify-email page
  const shouldHideNavBar = route.type === "verify-email";

  const userId = unwrapOk(result);
  if (userId === null)
    return (
      <div className={styles.container}>
        <NotLoggedIn />
      </div>
    );

  return (
    <div className={styles.layoutContainer}>
      {shouldHideNavBar ? null : (
        <>
          <UserGreeting userId={userId} />

          <NavBar>
            <NavItem route={{ type: "profile" }}>
              {t("frontend.nav.profile")}
            </NavItem>
            <NavItem route={{ type: "sessions-overview" }}>
              {t("frontend.nav.sessions")}
            </NavItem>
          </NavBar>
        </>
      )}

      <main>{children}</main>

      <Footer
        imprint={appConfig.branding?.imprint}
        tosUri={appConfig.branding?.tosUri}
        policyUri={appConfig.branding?.policyUri}
      />
    </div>
  );
};

export default Layout;
