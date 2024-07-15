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

import IconSignOut from "@vector-im/compound-design-tokens/assets/web/icons/sign-out";
import { Button } from "@vector-im/compound-web";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import * as Dialog from "../Dialog";
import LoadingSpinner from "../LoadingSpinner/LoadingSpinner";

/**
 * Generic end session button
 * Handles loading state while endSession is in progress
 */
const EndSessionButton: React.FC<
  React.PropsWithChildren<{ endSession: () => Promise<void> }>
> = ({ children, endSession }) => {
  const [inProgress, setInProgress] = useState(false);
  const [open, setOpen] = useState(false);
  const { t } = useTranslation();

  const onConfirm = async (
    e: React.MouseEvent<HTMLButtonElement>,
  ): Promise<void> => {
    e.preventDefault();

    setInProgress(true);
    try {
      await endSession();
      setOpen(false);
    } catch (error) {
      console.error("Failed to end session", error);
    }
    setInProgress(false);
  };

  return (
    <Dialog.Dialog
      open={open}
      onOpenChange={setOpen}
      trigger={
        <Button kind="secondary" destructive size="sm" Icon={IconSignOut}>
          {t("frontend.end_session_button.text")}
        </Button>
      }
    >
      <Dialog.Title>
        {t("frontend.end_session_button.confirmation_modal_title")}
      </Dialog.Title>

      {children && <Dialog.Description>{children}</Dialog.Description>}

      <Button
        type="button"
        kind="primary"
        destructive
        onClick={onConfirm}
        disabled={inProgress}
        Icon={inProgress ? undefined : IconSignOut}
      >
        {inProgress && <LoadingSpinner inline />}
        {t("frontend.end_session_button.text")}
      </Button>

      <Dialog.Close asChild>
        <Button kind="tertiary">{t("action.cancel")}</Button>
      </Dialog.Close>
    </Dialog.Dialog>
  );
};

export default EndSessionButton;
