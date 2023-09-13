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

import IconDelete from "@vector-im/compound-design-tokens/icons/delete.svg";
import { Body } from "@vector-im/compound-web";
import { atom, useSetAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithMutation } from "jotai-urql";
import { useTransition, ComponentProps, useState } from "react";

import { FragmentType, graphql, useFragment } from "../../gql";
import { Link } from "../../routing";
import ConfirmationModal from "../ConfirmationModal/ConfirmationModal";

import styles from "./UserEmail.module.css";

// This component shows a single user email address, with controls to verify it,
// resend the verification email, remove it, and set it as the primary email address.

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment UserEmail_email on UserEmail {
    id
    email
    confirmedAt
  }
`);

const REMOVE_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation RemoveEmail($id: ID!) {
    removeEmail(input: { userEmailId: $id }) {
      status

      user {
        id
      }
    }
  }
`);

const SET_PRIMARY_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation SetPrimaryEmail($id: ID!) {
    setPrimaryEmail(input: { userEmailId: $id }) {
      status
      user {
        id
        primaryEmail {
          id
        }
      }
    }
  }
`);

const removeEmailFamily = atomFamily((id: string) => {
  const removeEmail = atomWithMutation(REMOVE_EMAIL_MUTATION);

  // A proxy atom which pre-sets the id variable in the mutation
  const removeEmailAtom = atom(
    (get) => get(removeEmail),
    (_get, set) => set(removeEmail, { id }),
  );

  return removeEmailAtom;
});

const setPrimaryEmailFamily = atomFamily((id: string) => {
  const setPrimaryEmail = atomWithMutation(SET_PRIMARY_EMAIL_MUTATION);

  // A proxy atom which pre-sets the id variable in the mutation
  const setPrimaryEmailAtom = atom(
    (get) => get(setPrimaryEmail),
    (_get, set) => set(setPrimaryEmail, { id }),
  );

  return setPrimaryEmailAtom;
});

const DeleteButton: React.FC<{ disabled?: boolean; onClick?: () => void }> = ({
  disabled,
  onClick,
}) => (
  <button
    disabled={disabled}
    onClick={onClick}
    className={styles.userEmailDelete}
    title="Remove email address"
  >
    <IconDelete className={styles.userEmailDeleteIcon} />
  </button>
);

const DeleteButtonWithConfirmation: React.FC<
  ComponentProps<typeof DeleteButton>
> = ({ onClick, ...rest }) => {
  const [isConfirming, setIsConfirming] = useState(false);
  const onRequestConfirmation = onClick
    ? (): void => {
        setIsConfirming(true);
      }
    : undefined;

  const onConfirm = (): void => {
    onClick?.();
    setIsConfirming(false);
  };

  const onDeny = (): void => setIsConfirming(false);

  return (
    <>
      <DeleteButton onClick={onRequestConfirmation} {...rest} />
      {isConfirming && (
        <ConfirmationModal
          isOpen={isConfirming}
          onDeny={onDeny}
          onConfirm={onConfirm}
        >
          <Body>Are you sure you want to remove this email?</Body>
        </ConfirmationModal>
      )}
    </>
  );
};

const UserEmail: React.FC<{
  email: FragmentType<typeof FRAGMENT>;
  onRemove?: () => void;
  onSetPrimary?: () => void;
  isPrimary?: boolean;
  highlight?: boolean;
}> = ({ email, isPrimary, highlight, onSetPrimary, onRemove }) => {
  const [pending, startTransition] = useTransition();
  const data = useFragment(FRAGMENT, email);
  const setPrimaryEmail = useSetAtom(setPrimaryEmailFamily(data.id));
  const removeEmail = useSetAtom(removeEmailFamily(data.id));

  const onRemoveClick = (): void => {
    startTransition(() => {
      removeEmail().then(() => {
        // Call the onRemove callback if provided
        onRemove?.();
      });
    });
  };

  const onSetPrimaryClick = (): void => {
    startTransition(() => {
      setPrimaryEmail().then(() => {
        // Call the onSetPrimary callback if provided
        onSetPrimary?.();
      });
    });
  };

  return (
    <div className={styles.userEmail}>
      {isPrimary ? <Body>Primary email</Body> : <Body>Email</Body>}

      <div className={styles.userEmailLine}>
        <div className={styles.userEmailField}>{data.email}</div>
        <DeleteButtonWithConfirmation
          disabled={isPrimary || pending}
          onClick={onRemoveClick}
        />
      </div>
      {data.confirmedAt && !isPrimary && (
        <button
          className={styles.link}
          disabled={pending}
          onClick={onSetPrimaryClick}
        >
          Make primary
        </button>
      )}
      {!data.confirmedAt && (
        <div>
          <span className={styles.userEmailUnverified}>Unverified</span> |{" "}
          <Link kind="button" route={{ type: "verify-email", id: data.id }}>
            Retry verification
          </Link>
        </div>
      )}
    </div>
  );
};

export default UserEmail;
