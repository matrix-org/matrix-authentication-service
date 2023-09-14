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
import { ReactNode, useState } from "react";

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
 * controls it's own open state
 * calls onDeny on cancel, esc, or overlay click
 * calls onConfirm on confirm click
 */
const ConfirmationModal: React.FC<React.PropsWithChildren<Props>> = ({
  onConfirm,
  onDeny,
  className,
  children,
  trigger,
  title,
}) => {
  const [isOpen, setIsOpen] = useState(false);

  const onClose = (callback?: () => void) => (): void => {
    setIsOpen(false);
    callback?.();
  };

  // radix's autofocus doesn't work for some reason
  // maybe https://www.radix-ui.com/primitives/docs/guides/composition#your-component-must-forward-ref
  // when this is replaced with compound's own/wrapped dialog this should be fixed
  // until then, focus the cancel button here
  const onOpenAutoFocus = (e: Event): void => {
    const focusButtonKind = onDeny ? "tertiary" : "destructive";
    (e.target as Element)
      ?.querySelector<HTMLButtonElement>(
        `button[data-kind="${focusButtonKind}"]`,
      )
      ?.focus();
  };
  return (
    <Root open={isOpen} onOpenChange={setIsOpen}>
      <Trigger asChild>{trigger}</Trigger>
      <Portal>
        <Overlay className={styles.overlay} onClick={onClose(onDeny)} />
        <Content
          className={classNames(styles.content, className)}
          onEscapeKeyDown={onClose(onDeny)}
          onOpenAutoFocus={onOpenAutoFocus}
        >
          <Title>{title}</Title>
          <Description>{children}</Description>
          <div className={styles.buttons}>
            {onDeny && (
              <Cancel asChild>
                <Button kind="tertiary" size="sm" onClick={onClose(onDeny)}>
                  Cancel
                </Button>
              </Cancel>
            )}
            <Action asChild>
              <Button kind="destructive" size="sm" onClick={onClose(onConfirm)}>
                Continue
              </Button>
            </Action>
          </div>
        </Content>
      </Portal>
    </Root>
  );
};

export default ConfirmationModal;
