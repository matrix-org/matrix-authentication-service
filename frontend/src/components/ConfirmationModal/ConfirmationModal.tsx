// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
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

import { Button } from "@vector-im/compound-web";
import { ReactNode } from "react";
import { Translation } from "react-i18next";

import { Dialog, Title, Description, Close, Actions } from "../Dialog";

type Props = {
  onConfirm: () => void;
  title?: ReactNode | string;
  // element used to trigger opening of modal
  trigger: ReactNode;
};

/**
 * Generic confirmation modal
 * controls its own open state
 * calls onConfirm on confirm click
 */
const ConfirmationModal: React.FC<React.PropsWithChildren<Props>> = ({
  onConfirm,
  children,
  trigger,
  title,
}) => (
  <Translation>
    {(t): ReactNode => (
      <Dialog trigger={trigger}>
        <Title>{title}</Title>

        {children && <Description>{children}</Description>}

        <Actions>
          <Close asChild>
            <Button kind="primary" destructive onClick={onConfirm}>
              {t("action.continue")}
            </Button>
          </Close>

          <Close asChild>
            <Button kind="tertiary">{t("action.cancel")}</Button>
          </Close>
        </Actions>
      </Dialog>
    )}
  </Translation>
);

export default ConfirmationModal;
