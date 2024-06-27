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

import {
  EditInPlace,
  ErrorMessage,
  HelpMessage,
} from "@vector-im/compound-web";
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
  onAdd: (id: string) => Promise<void>;
}> = ({ userId, onAdd }) => {
  const { t } = useTranslation();
  const [addEmailResult, addEmail] = useMutation(ADD_EMAIL_MUTATION);
  if (addEmailResult.error) throw addEmailResult.error;

  const handleSubmit = async (
    e: React.FormEvent<HTMLFormElement>,
  ): Promise<void> => {
    e.preventDefault();

    const formData = new FormData(e.currentTarget);
    const email = formData.get("input") as string;
    const result = await addEmail({ userId, email });

    // Don't clear the form if the email was invalid or already exists
    if (result.data?.addEmail.status !== "ADDED") {
      return;
    }

    if (!result.data?.addEmail.email?.id) {
      throw new Error("Unexpected response from server");
    }

    // Call the onAdd callback
    await onAdd(result.data?.addEmail.email?.id);
  };

  const status = addEmailResult.data?.addEmail.status ?? null;
  const violations = addEmailResult.data?.addEmail.violations ?? [];

  return (
    <EditInPlace
      onSave={handleSubmit}
      required
      type="email"
      serverInvalid={
        status === "INVALID" || status === "EXISTS" || status === "DENIED"
      }
      label={t("frontend.add_email_form.email_field_label")}
      helpLabel={t("frontend.add_email_form.email_field_help")}
      saveButtonLabel={t("action.save")}
      savingLabel={t("common.saving")}
      savedLabel={t("common.saved")}
      cancelButtonLabel={t("action.cancel")}
    >
      <ErrorMessage match="typeMismatch" forceMatch={status === "INVALID"}>
        {t("frontend.add_email_form.email_invalid_error")}
      </ErrorMessage>

      {status === "EXISTS" && (
        <ErrorMessage>
          {t("frontend.add_email_form.email_exists_error")}
        </ErrorMessage>
      )}

      {status === "DENIED" && (
        <>
          <ErrorMessage>
            {t("frontend.add_email_form.email_denied_error")}
          </ErrorMessage>

          {violations.map((violation) => (
            // XXX: those messages are bad, but it's better to show them than show a generic message
            <HelpMessage key={violation}>{violation}</HelpMessage>
          ))}
        </>
      )}
    </EditInPlace>
  );
};

export default AddEmailForm;
