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
  createLazyFileRoute,
  useRouter,
  useSearch,
} from "@tanstack/react-router";
import IconLockSolid from "@vector-im/compound-design-tokens/assets/web/icons/lock-solid";
import { Alert, Form } from "@vector-im/compound-web";
import { FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery } from "urql";

import BlockList from "../components/BlockList";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import PageHeading from "../components/PageHeading";
import PasswordCreationDoubleInput from "../components/PasswordCreationDoubleInput";
import { graphql } from "../gql";
import { SetPasswordStatus } from "../gql/graphql";
import { translateSetPasswordError } from "../i18n/password_changes";

const QUERY = graphql(/* GraphQL */ `
  query PasswordRecoveryQuery {
    siteConfig {
      id
      ...PasswordCreationDoubleInput_siteConfig
    }
  }
`);

const RECOVER_PASSWORD_MUTATION = graphql(/* GraphQL */ `
  mutation RecoverPassword($ticket: String!, $newPassword: String!) {
    setPasswordByRecovery(
      input: { ticket: $ticket, newPassword: $newPassword }
    ) {
      status
    }
  }
`);

export const Route = createLazyFileRoute("/password/recovery/")({
  component: RecoverPassword,
});

function RecoverPassword(): React.ReactNode {
  const { t } = useTranslation();
  const { ticket } = useSearch({
    from: "/password/recovery/",
  });
  const [queryResult] = useQuery({ query: QUERY });
  const router = useRouter();
  if (queryResult.error) throw queryResult.error;
  const siteConfig = queryResult.data?.siteConfig;
  if (!siteConfig) throw Error(); // This should never happen

  const [result, changePassword] = useMutation(RECOVER_PASSWORD_MUTATION);

  const onSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();

    const formData = new FormData(event.currentTarget);

    const newPassword = formData.get("new_password") as string;
    const newPasswordAgain = formData.get("new_password_again") as string;

    if (newPassword !== newPasswordAgain) {
      throw new Error("passwords mismatch; this should be checked by the form");
    }

    const response = await changePassword({ ticket, newPassword });

    if (
      response.data?.setPasswordByRecovery.status === SetPasswordStatus.Allowed
    ) {
      // Redirect to the application root using a full page load
      // The MAS backend will then redirect to the login page
      // Unfortunately this won't work in dev mode (`npm run dev`)
      // as the backend isn't involved there.
      const location = router.buildLocation({ to: "/" });
      window.location.href = location.href;
    }
  };

  const unhandleableError = result.error !== undefined;

  const errorMsg: string | undefined = translateSetPasswordError(
    t,
    result.data?.setPasswordByRecovery.status,
  );

  return (
    <Layout>
      <BlockList>
        <PageHeading
          Icon={IconLockSolid}
          title={t("frontend.password_reset.title")}
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

          <PasswordCreationDoubleInput
            siteConfig={siteConfig}
            forceShowNewPasswordInvalid={
              (result.data &&
                result.data.setPasswordByRecovery.status ==
                  SetPasswordStatus.InvalidNewPassword) ||
              false
            }
          />

          <Form.Submit kind="primary" disabled={result.fetching}>
            {!!result.fetching && <LoadingSpinner inline />}
            {t("action.save_and_continue")}
          </Form.Submit>
        </Form.Root>
      </BlockList>
    </Layout>
  );
}
