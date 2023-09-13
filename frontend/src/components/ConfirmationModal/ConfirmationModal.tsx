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

import classNames from "classnames";
import { ComponentProps, ReactNode } from "react";
import Modal from "react-modal";

import styles from "./ConfirmationModal.module.css";

type Props = ComponentProps<typeof Modal> & { buttons?: ReactNode };
const ConfirmationModal: React.FC<React.PropsWithChildren<Props>> = ({
  buttons,
  className,
  children,
  ...rest
}) => (
  <Modal
    shouldCloseOnOverlayClick
    {...rest}
    className={classNames(styles.confirmationModal, className)}
  >
    {children}
    {buttons && <div className={styles.buttons}>{buttons}</div>}
  </Modal>
);

export default ConfirmationModal;
