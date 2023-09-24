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

import IconArrowLeft from "@vector-im/compound-design-tokens/icons/arrow-left.svg";
import { H3, IconButton } from "@vector-im/compound-web";
import { PropsWithChildren } from "react";

import { useNavigationLink } from "../../routing";
import { Route } from "../../routing/routes";
import LoadingSpinner from "../LoadingSpinner";

import styles from "./SessionHeader.module.css";

const BackButton: React.FC<{ backToRoute: Route }> = ({ backToRoute }) => {
  const { onClick, pending } = useNavigationLink(backToRoute);

  return (
    <IconButton type="button" onClick={onClick}>
      {pending ? <LoadingSpinner /> : <IconArrowLeft />}
    </IconButton>
  );
};

const SessionHeader: React.FC<PropsWithChildren<{ backToRoute: Route }>> = ({
  children,
  backToRoute,
}) => (
  <header className={styles.header}>
    <BackButton backToRoute={backToRoute} />
    <H3>{children}</H3>
  </header>
);

export default SessionHeader;
