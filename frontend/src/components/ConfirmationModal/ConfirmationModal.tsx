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

import {
  Root,
  Portal,
  Overlay,
  Content,
  Trigger,
  Title,
  Description,
  Action,
  Cancel,
} from "@radix-ui/react-alert-dialog";
import { Button } from "@vector-im/compound-web";
import classNames from "classnames";
import { ReactNode } from "react";
import { Translation } from "react-i18next";

import styles from "./ConfirmationModal.module.css";

type Props = {
  onConfirm: () => void;
  onDeny?: () => void;
  title?: ReactNode | string;
  // element used to trigger opening of modal
  trigger: ReactNode;
  className?: string;
};
/**
 * Generic confirmation modal
 * controls its own open state
 * calls onDeny on cancel or esc
 * calls onConfirm on confirm click
 */
const ConfirmationModal: React.FC<React.PropsWithChildren<Props>> = ({
  onConfirm,
  onDeny,
  className,
  children,
  trigger,
  title,
}) => (
  <Translation>
    {(t): ReactNode => (
      <Root>
        <Trigger asChild>{trigger}</Trigger>
        <Portal>
          <Overlay className={styles.overlay} />
          <Content
            className={classNames(styles.content, className)}
            onEscapeKeyDown={(event): void => {
              if (onDeny) {
                onDeny();
              } else {
                // if there is no deny callback, we should prevent the escape key from closing the modal
                event.preventDefault();
              }
            }}
          >
            <Title>{title}</Title>
            <Description>{children}</Description>
            <div className={styles.buttons}>
              {onDeny && (
                <Cancel asChild>
                  <Button kind="tertiary" size="sm" onClick={onDeny}>
                    {t("action.cancel")}
                  </Button>
                </Cancel>
              )}
              <Action asChild>
                <Button kind="destructive" size="sm" onClick={onConfirm}>
                  {t("action.continue")}
                </Button>
              </Action>
            </div>
          </Content>
        </Portal>
      </Root>
    )}
  </Translation>
);

export default ConfirmationModal;
