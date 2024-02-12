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

import { Alert, Form } from "@vector-im/compound-web";
import { useRef } from "react";
import { useTranslation } from "react-i18next";
import { useMutation } from "urql";

import { graphql } from "../../gql";

const ADD_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation AddEmail($userId: ID!, $email: String!) {
    addEmail(input: { userId: $userId, email: $email }) {
      status
      violations
      email {
        id
        ...UserEmail_email
      }
    }
  }
`);

const AddEmailForm: React.FC<{
  userId: string;
  onAdd?: (id: string) => void;
}> = ({ userId, onAdd }) => {
  const { t } = useTranslation();
  const formRef = useRef<HTMLFormElement>(null);
  const fieldRef = useRef<HTMLInputElement>(null);
  const [addEmailResult, addEmail] = useMutation(ADD_EMAIL_MUTATION);
  if (addEmailResult.error) throw addEmailResult.error;

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>): void => {
    e.preventDefault();

    const formData = new FormData(e.currentTarget);
    const email = formData.get("email") as string;
    addEmail({ userId, email }).then((result) => {
      // Don't clear the form if the email was invalid or already exists
      if (result.data?.addEmail.status !== "ADDED") {
        return;
      }

      if (!result.data?.addEmail.email?.id) {
        throw new Error("Unexpected response from server");
      }

      // Call the onAdd callback if provided
      onAdd?.(result.data?.addEmail.email?.id);

      // Reset the form
      formRef.current?.reset();
    });
  };

  const status = addEmailResult.data?.addEmail.status ?? null;
  const emailExists = status === "EXISTS";
  const emailInvalid = status === "INVALID";
  const emailDenied = status === "DENIED";
  const violations = addEmailResult.data?.addEmail.violations ?? [];

  return (
    <>
      <Form.Root ref={formRef} onSubmit={handleSubmit}>
        {emailExists && (
          <Alert
            type="info"
            title={t("frontend.add_email_form.email_exists_alert.title")}
          >
            {t("frontend.add_email_form.email_exists_alert.text")}
          </Alert>
        )}

        {emailInvalid && (
          <Alert
            type="critical"
            title={t("frontend.add_email_form.email_invalid_alert.title")}
          >
            {t("frontend.add_email_form.email_invalid_alert.text")}
          </Alert>
        )}

        {emailDenied && (
          <Alert
            type="critical"
            title={t("frontend.add_email_form.email_denied_alert.title")}
          >
            {t("frontend.add_email_form.email_denied_alert.text")}
            <ul>
              {violations.map((violation, index) => (
                <li key={index}>• {violation}</li>
              ))}
            </ul>
          </Alert>
        )}

        <Form.Field
          name="email"
          serverInvalid={emailInvalid || emailExists || emailDenied}
        >
          <Form.Label>
            {t("frontend.add_email_form.email_field_label")}
          </Form.Label>
          <Form.TextControl
            disabled={addEmailResult.fetching}
            type="email"
            autoComplete="email"
            ref={fieldRef}
          />
        </Form.Field>

        <Form.Submit
          size="sm"
          disabled={addEmailResult.fetching}
          className="self-start"
        >
          {t("common.add")}
        </Form.Submit>
      </Form.Root>
    </>
  );
};

export default AddEmailForm;
