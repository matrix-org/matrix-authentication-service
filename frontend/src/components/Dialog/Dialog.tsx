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

import {
  Root as DialogRoot,
  Trigger,
  Portal,
  Close,
  Title as DialogTitle,
  Overlay as DialogOverlay,
  Content as DialogContent,
} from "@radix-ui/react-dialog";
import IconClose from "@vector-im/compound-design-tokens/assets/web/icons/close";
import { Glass, Tooltip } from "@vector-im/compound-web";
import { PropsWithChildren } from "react";
import { useTranslation } from "react-i18next";
import { Drawer } from "vaul";

import styles from "./Dialog.module.css";

// The granularity of this value is kind of arbitrary: it distinguishes exactly
// the platforms that this library needs to know about in order to correctly
// implement the designs.
let platform: "android" | "ios" | "other" = "other";

if (/android/i.test(navigator.userAgent)) {
  platform = "android";
  // We include 'Mac' here and double-check for touch support because iPads on
  // iOS 13 pretend to be a MacOS desktop
} else if (
  /iPad|iPhone|iPod|Mac/.test(navigator.userAgent) &&
  "ontouchend" in document
) {
  platform = "ios";
}

type Props = React.PropsWithChildren<{
  trigger?: React.ReactNode;
  open?: boolean;
  asDrawer?: boolean;
  onOpenChange?: (open: boolean) => void;
}>;

export const Dialog: React.FC<Props> = ({
  trigger,
  open,
  asDrawer,
  onOpenChange,
  children,
}) => {
  if (typeof asDrawer !== "boolean") {
    asDrawer = platform !== "other";
  }

  const { t } = useTranslation();

  if (asDrawer) {
    return (
      <Drawer.Root open={open} onOpenChange={onOpenChange}>
        {trigger && <Trigger asChild>{trigger}</Trigger>}
        <Portal>
          <Drawer.Overlay className={styles.overlay} />
          <Drawer.Content className={styles.drawer} data-platform={platform}>
            <div className={styles.body}>{children}</div>
          </Drawer.Content>
        </Portal>
      </Drawer.Root>
    );
  }

  return (
    <DialogRoot open={open} onOpenChange={onOpenChange}>
      {trigger && <Trigger asChild>{trigger}</Trigger>}
      <Portal>
        {/* This container has a fixed position and scrolls over the Y axis if needed */}
        <DialogOverlay className={styles.scrollContainer}>
          {/* This container is used as a flexbox parent to center the dialog */}
          <div className={styles.container}>
            <Glass className={styles.dialog}>
              <DialogContent className={styles.body}>
                {children}

                <Tooltip label={t("action.close")}>
                  <Close className={styles.close}>
                    <IconClose />
                  </Close>
                </Tooltip>
              </DialogContent>
            </Glass>
          </div>
        </DialogOverlay>
      </Portal>
    </DialogRoot>
  );
};

export const Title: React.FC<PropsWithChildren> = ({ children }) => (
  <DialogTitle className={styles.title}>{children}</DialogTitle>
);

export { Description, Close } from "@radix-ui/react-dialog";
