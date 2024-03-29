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

import { createLink } from "@tanstack/react-router";
import cx from "classnames";
import { forwardRef } from "react";

import { DeviceType } from "../../gql/graphql";
import ClientAvatar from "../Session/ClientAvatar";
import DeviceTypeIcon from "../Session/DeviceTypeIcon";

import styles from "./SessionCard.module.css";

export const Root: React.FC<React.PropsWithChildren> = ({ children }) => (
  <section className={styles.sessionCardRoot}>{children}</section>
);

type BodyProps = React.PropsWithChildren<{
  disabled?: boolean;
  compact?: boolean;
  className?: string;
}>;
export const LinkBody = createLink(
  forwardRef<HTMLAnchorElement, BodyProps>(
    ({ children, disabled, compact, className, ...props }, ref) => {
      return (
        <a
          className={cx(
            className,
            styles.sessionCard,
            compact && styles.compact,
            disabled && styles.disabled,
          )}
          {...props}
          ref={ref}
        >
          {children}
        </a>
      );
    },
  ),
);

export const Body: React.FC<BodyProps> = ({ children, compact, disabled }) => (
  <div
    className={cx(
      styles.sessionCard,
      compact && styles.compact,
      disabled && styles.disabled,
    )}
  >
    {children}
  </div>
);

type HeaderProps = React.PropsWithChildren<{ type: DeviceType }>;
export const Header: React.FC<HeaderProps> = ({ type, children }) => (
  <header className={styles.cardHeader}>
    <DeviceTypeIcon deviceType={type} />
    <div className={styles.content}>{children}</div>
  </header>
);

type NameProps = { name: string };
export const Name: React.FC<NameProps> = ({ name }) => (
  <div className={styles.name}>{name}</div>
);

type ClientProps = { name: string; logoUri?: string };
export const Client: React.FC<ClientProps> = ({ name, logoUri }) => (
  <div className={styles.client}>
    <ClientAvatar name={name} size="var(--cpd-space-5x)" logoUri={logoUri} />
    {name}
  </div>
);

export const Metadata: React.FC<React.PropsWithChildren> = ({ children }) => (
  <ul className={styles.metadata}>{children}</ul>
);

export const Info: React.FC<React.PropsWithChildren<{ label: string }>> = ({
  label,
  children,
}) => (
  <li>
    <div className={styles.key}>{label}</div>
    <div className={styles.value}>{children}</div>
  </li>
);

export const Action: React.FC<React.PropsWithChildren> = ({ children }) => (
  <div className={styles.action}>{children}</div>
);
