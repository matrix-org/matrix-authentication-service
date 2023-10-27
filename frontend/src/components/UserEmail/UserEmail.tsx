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

import IconDelete from "@vector-im/compound-design-tokens/icons/delete.svg?react";
import { Form, IconButton, Text, Tooltip } from "@vector-im/compound-web";
import { atom, useSetAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithMutation } from "jotai-urql";
import { useTransition, ComponentProps, ReactNode } from "react";
import { Translation, useTranslation } from "react-i18next";

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
  <Translation>
    {(t): ReactNode => (
      <Tooltip label={t("frontend.user_email.delete_button_title")}>
        <IconButton
          type="button"
          disabled={disabled}
          className="m-2"
          onClick={onClick}
          size="var(--cpd-space-8x)"
        >
          <IconDelete className={styles.userEmailDeleteIcon} />
        </IconButton>
      </Tooltip>
    )}
  </Translation>
);

const DeleteButtonWithConfirmation: React.FC<
  ComponentProps<typeof DeleteButton>
> = ({ onClick, ...rest }) => {
  const { t } = useTranslation();
  const onConfirm = (): void => {
    onClick?.();
  };

  // NOOP function, otherwise we dont render a cancel button
  const onDeny = (): void => {};

  return (
    <>
      <ConfirmationModal
        trigger={<DeleteButton {...rest} />}
        onDeny={onDeny}
        onConfirm={onConfirm}
      >
        <Text>
          {t("frontend.user_email.delete_button_confirmation_modal.body")}
        </Text>
      </ConfirmationModal>
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
  const { t } = useTranslation();

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
    <Form.Root>
      <Form.Field name="email">
        <Form.Label>
          {isPrimary
            ? t("frontend.user_email.primary_email")
            : t("frontend.user_email.email")}
        </Form.Label>
        <div className="flex">
          <Form.TextControl
            type="email"
            readOnly
            value={data.email}
            className={styles.userEmailField}
          />
          <DeleteButtonWithConfirmation
            disabled={isPrimary || pending}
            onClick={onRemoveClick}
          />
        </div>

        <Form.HelpMessage>
          {data.confirmedAt && !isPrimary && (
            <button
              className={styles.link}
              disabled={pending}
              onClick={onSetPrimaryClick}
            >
              {t("frontend.user_email.make_primary_button")}
            </button>
          )}
          {!data.confirmedAt && (
            <>
              <span className={styles.userEmailUnverified}>
                {t("frontend.user_email.unverified")}
              </span>{" "}
              |{" "}
              <Link kind="button" route={{ type: "verify-email", id: data.id }}>
                {t("frontend.user_email.retry_button")}
              </Link>
            </>
          )}
        </Form.HelpMessage>
      </Form.Field>
    </Form.Root>
  );
};

export default UserEmail;
