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

import { createFileRoute, notFound, useRouter } from "@tanstack/react-router";
import IconLockSolid from "@vector-im/compound-design-tokens/icons/lock-solid.svg?react";
import { Alert, Form, Separator } from "@vector-im/compound-web";
import { FormEvent, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery } from "urql";

import BlockList from "../components/BlockList";
import { ButtonLink } from "../components/ButtonLink";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import PageHeading from "../components/PageHeading";
import { graphql } from "../gql";
import { SetPasswordStatus } from "../gql/graphql";

const CURRENT_VIEWER_QUERY = graphql(/* GraphQL */ `
  query CurrentViewerQuery {
    viewer {
      __typename
      ... on Node {
        id
      }
    }
  }
`);

const CHANGE_PASSWORD_MUTATION = graphql(/* GraphQL */ `
  mutation ChangePassword(
    $userId: ID!
    $oldPassword: String!
    $newPassword: String!
  ) {
    setPassword(
      input: {
        userId: $userId
        currentPassword: $oldPassword
        newPassword: $newPassword
      }
    ) {
      status
    }
  }
`);

export const Route = createFileRoute("/password/change/")({
  async loader({ context, abortController: { signal } }) {
    const viewer = await context.client.query(
      CURRENT_VIEWER_QUERY,
      {},
      { fetchOptions: { signal } },
    );
    if (viewer.error) throw viewer.error;
    if (viewer.data?.viewer.__typename !== "User") throw notFound();
  },

  component: ChangePassword,
});

function ChangePassword(): React.ReactNode {
  const { t } = useTranslation();
  const [viewer] = useQuery({ query: CURRENT_VIEWER_QUERY });
  const router = useRouter();
  if (viewer.error) throw viewer.error;
  if (viewer.data?.viewer.__typename !== "User") throw notFound();
  const userId = viewer.data.viewer.id;

  const currentPasswordRef = useRef<HTMLInputElement>(null);
  const newPasswordRef = useRef<HTMLInputElement>(null);
  const newPasswordAgainRef = useRef<HTMLInputElement>(null);

  const [result, changePassword] = useMutation(CHANGE_PASSWORD_MUTATION);

  const onSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();

    const formData = new FormData(event.currentTarget);

    const oldPassword = formData.get("current_password") as string;
    const newPassword = formData.get("new_password") as string;
    const newPasswordAgain = formData.get("new_password_again") as string;

    if (newPassword !== newPasswordAgain) {
      throw new Error("passwords mismatch; this should be checked by the form");
    }

    const response = await changePassword({ userId, oldPassword, newPassword });

    if (response.data?.setPassword.status === SetPasswordStatus.Allowed) {
      router.navigate({ to: "/password/change/success" });
    }
  };

  const unhandleableError = result.error !== undefined;

  const errorMsg: string | undefined = ((): string | undefined => {
    switch (result.data?.setPassword.status) {
      case SetPasswordStatus.NoCurrentPassword:
        return t(
          "frontend.password_change.failure.description.no_current_password",
        );
      case SetPasswordStatus.PasswordChangesDisabled:
        return t(
          "frontend.password_change.failure.description.password_changes_disabled",
        );

      case SetPasswordStatus.WrongPassword:
      case SetPasswordStatus.InvalidNewPassword:
        // These cases are shown as inline errors in the form itself.
        return undefined;

      case SetPasswordStatus.Allowed:
      case undefined:
        return undefined;

      default:
        throw new Error(
          `unexpected error when changing password: ${result.data!.setPassword.status}`,
        );
    }
  })();

  return (
    <Layout>
      <BlockList>
        <PageHeading
          Icon={IconLockSolid}
          title={t("frontend.password_change.title")}
          subtitle={t("frontend.password_change.subtitle")}
        />

        <Form.Root onSubmit={onSubmit} method="POST">
          {/*
            In normal operation, the submit event should be `preventDefault()`ed.
            method = POST just prevents sending passwords in the query string,
            which could be logged, if for some reason the event handler fails.
          */}
          {unhandleableError && (
            <Alert
              type="critical"
              title={t("frontend.password_change.failure.title")}
            >
              {t("frontend.password_change.failure.description.unspecified")}
            </Alert>
          )}

          {errorMsg !== undefined && (
            <Alert
              type="critical"
              title={t("frontend.password_change.failure.title")}
            >
              {errorMsg}
            </Alert>
          )}

          <Form.Field
            name="current_password"
            serverInvalid={
              result.data?.setPassword.status ===
              SetPasswordStatus.WrongPassword
            }
          >
            <Form.Label>
              {t("frontend.password_change.current_password_label")}
            </Form.Label>

            <Form.PasswordControl
              required
              autoComplete="current-password"
              ref={currentPasswordRef}
            />

            <Form.ErrorMessage match="valueMissing">
              {t("frontend.errors.field_required")}
            </Form.ErrorMessage>

            {result.data &&
              result.data.setPassword.status ===
                SetPasswordStatus.WrongPassword && (
                <Form.ErrorMessage>
                  {t(
                    "frontend.password_change.failure.description.wrong_password",
                  )}
                </Form.ErrorMessage>
              )}
          </Form.Field>

          <Separator />

          <Form.Field name="new_password">
            <Form.Label>
              {t("frontend.password_change.new_password_label")}
            </Form.Label>

            <Form.PasswordControl
              required
              autoComplete="new-password"
              ref={newPasswordRef}
              onBlur={() =>
                newPasswordAgainRef.current!.value &&
                newPasswordAgainRef.current!.reportValidity()
              }
            />

            {/* TODO Show a password bar. https://github.com/matrix-org/matrix-authentication-service/issues/2854 */}

            <Form.ErrorMessage match="valueMissing">
              {t("frontend.errors.field_required")}
            </Form.ErrorMessage>

            {result.data &&
              result.data.setPassword.status ===
                SetPasswordStatus.InvalidNewPassword && (
                <Form.ErrorMessage>
                  {t(
                    "frontend.password_change.failure.description.invalid_new_password",
                  )}
                </Form.ErrorMessage>
              )}
          </Form.Field>

          <Form.Field name="new_password_again">
            {/*
            TODO This field has validation defects,
            some caused by Radix-UI upstream bugs.
            https://github.com/matrix-org/matrix-authentication-service/issues/2855
          */}
            <Form.Label>
              {t("frontend.password_change.new_password_again_label")}
            </Form.Label>

            <Form.PasswordControl
              required
              ref={newPasswordAgainRef}
              autoComplete="new-password"
            />

            <Form.ErrorMessage match="valueMissing">
              {t("frontend.errors.field_required")}
            </Form.ErrorMessage>

            <Form.ErrorMessage
              match={(v, form) => v !== form.get("new_password")}
            >
              {t("frontend.password_change.passwords_no_match")}
            </Form.ErrorMessage>

            <Form.SuccessMessage match="valid">
              {t("frontend.password_change.passwords_match")}
            </Form.SuccessMessage>
          </Form.Field>

          <Form.Submit kind="primary" disabled={result.fetching}>
            {!!result.fetching && <LoadingSpinner inline />}
            {t("action.save")}
          </Form.Submit>

          <ButtonLink to="/" kind="tertiary">
            {t("action.cancel")}
          </ButtonLink>
        </Form.Root>
      </BlockList>
    </Layout>
  );
}
