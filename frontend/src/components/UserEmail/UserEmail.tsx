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
import IconEmail from "@vector-im/compound-design-tokens/icons/email.svg?react";
import { Button, Form, IconButton, Tooltip } from "@vector-im/compound-web";
import { ComponentProps, ReactNode } from "react";
import { Translation, useTranslation } from "react-i18next";
import { useMutation } from "urql";

import { FragmentType, graphql, useFragment } from "../../gql";
import { Close, Description, Dialog, Title } from "../Dialog";
import { Link } from "../Link";

import styles from "./UserEmail.module.css";

// This component shows a single user email address, with controls to verify it,
// resend the verification email, remove it, and set it as the primary email address.

const FRAGMENT = graphql(/* GraphQL */ `
  fragment UserEmail_email on UserEmail {
    id
    email
    confirmedAt
  }
`);

const CONFIG_FRAGMENT = graphql(/* GraphQL */ `
  fragment UserEmail_siteConfig on SiteConfig {
    id
    emailChangeAllowed
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
  ComponentProps<typeof DeleteButton> & { email: string }
> = ({ email, onClick, ...rest }) => {
  const { t } = useTranslation();
  const onConfirm = (): void => {
    onClick?.();
  };

  // NOOP function, otherwise we dont render a cancel button
  const onDeny = (): void => {};

  return (
    <Dialog trigger={<DeleteButton {...rest} />}>
      <Title>
        {t("frontend.user_email.delete_button_confirmation_modal.body")}
      </Title>
      <Description className={styles.emailModalBox}>
        <IconEmail />
        <div>{email}</div>
      </Description>
      <div className="flex flex-col gap-4">
        <Close asChild>
          <Button
            kind="primary"
            destructive
            onClick={onConfirm}
            Icon={IconDelete}
          >
            {t("frontend.user_email.delete_button_confirmation_modal.action")}
          </Button>
        </Close>
        <Close asChild>
          <Button kind="tertiary" onClick={onDeny}>
            {t("action.cancel")}
          </Button>
        </Close>
      </div>
    </Dialog>
  );
};

const UserEmail: React.FC<{
  email: FragmentType<typeof FRAGMENT>;
  siteConfig: FragmentType<typeof CONFIG_FRAGMENT>;
  onRemove?: () => void;
  isPrimary?: boolean;
}> = ({ email, siteConfig, isPrimary, onRemove }) => {
  const { t } = useTranslation();
  const data = useFragment(FRAGMENT, email);
  const { emailChangeAllowed } = useFragment(CONFIG_FRAGMENT, siteConfig);

  const [setPrimaryResult, setPrimary] = useMutation(
    SET_PRIMARY_EMAIL_MUTATION,
  );
  const [removeResult, removeEmail] = useMutation(REMOVE_EMAIL_MUTATION);
  // Handle errors with the error boundary
  if (setPrimaryResult.error) throw setPrimaryResult.error;
  if (removeResult.error) throw removeResult.error;

  const onRemoveClick = (): void => {
    removeEmail({ id: data.id }).then(() => {
      // Call the onRemove callback if provided
      onRemove?.();
    });
  };

  const onSetPrimaryClick = (): void => {
    setPrimary({ id: data.id });
  };

  return (
    <Form.Root>
      <Form.Field name="email">
        <Form.Label>
          {isPrimary
            ? t("frontend.user_email.primary_email")
            : t("frontend.user_email.email")}
        </Form.Label>

        <div className="flex items-center gap-2">
          <Form.TextControl
            type="email"
            readOnly
            value={data.email}
            className={styles.userEmailField}
          />
          {!isPrimary && emailChangeAllowed && (
            <DeleteButtonWithConfirmation
              email={data.email}
              disabled={removeResult.fetching}
              onClick={onRemoveClick}
            />
          )}
        </div>

        {isPrimary && emailChangeAllowed && (
          <Form.HelpMessage>
            {t("frontend.user_email.cant_delete_primary")}
          </Form.HelpMessage>
        )}

        {data.confirmedAt && !isPrimary && emailChangeAllowed && (
          <Form.HelpMessage>
            <button
              type="button"
              className={styles.link}
              disabled={setPrimaryResult.fetching}
              onClick={onSetPrimaryClick}
            >
              {t("frontend.user_email.make_primary_button")}
            </button>
          </Form.HelpMessage>
        )}

        {!data.confirmedAt && (
          <Form.ErrorMessage>
            {t("frontend.user_email.not_verified")} |{" "}
            <Link to="/emails/$id/verify" params={{ id: data.id }}>
              {t("frontend.user_email.retry_button")}
            </Link>
          </Form.ErrorMessage>
        )}
      </Form.Field>
    </Form.Root>
  );
};

export default UserEmail;
