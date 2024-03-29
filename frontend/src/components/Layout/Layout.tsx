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

import cx from "classnames";
import { Suspense } from "react";
import { useQuery } from "urql";

import { graphql } from "../../gql";
import Footer from "../Footer";

import styles from "./Layout.module.css";

const QUERY = graphql(/* GraphQL */ `
  query FooterQuery {
    siteConfig {
      id
      ...Footer_siteConfig
    }
  }
`);

const AsyncFooter: React.FC = () => {
  const [result] = useQuery({
    query: QUERY,
  });

  if (result.error) {
    // We probably prefer to render an empty footer in case of an error
    return null;
  }

  const siteConfig = result.data?.siteConfig;
  if (!siteConfig) {
    // We checked for errors, this should never happen
    throw new Error();
  }

  return <Footer siteConfig={siteConfig} />;
};

const Layout: React.FC<{
  children?: React.ReactNode;
  wide?: boolean;
}> = ({ children, wide }) => (
  <div className={cx(styles.layoutContainer, wide && styles.wide)}>
    {children}

    <Suspense fallback={null}>
      <AsyncFooter />
    </Suspense>
  </div>
);

export default Layout;
