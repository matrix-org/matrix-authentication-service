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

import {
  Alert,
  Control,
  Field,
  Label,
  Root,
  Submit,
} from "@vector-im/compound-web";
import { useAtom } from "jotai";
import { atomWithMutation } from "jotai-urql";
import { useRef, useTransition } from "react";

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

const addUserEmailAtom = atomWithMutation(ADD_EMAIL_MUTATION);

const AddEmailForm: React.FC<{
  userId: string;
  onAdd?: (id: string) => void;
}> = ({ userId, onAdd }) => {
  const formRef = useRef<HTMLFormElement>(null);
  const fieldRef = useRef<HTMLInputElement>(null);
  const [addEmailResult, addEmail] = useAtom(addUserEmailAtom);
  const [pending, startTransition] = useTransition();

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>): void => {
    e.preventDefault();

    const formData = new FormData(e.currentTarget);
    const email = formData.get("email") as string;
    startTransition(() => {
      addEmail({ userId, email }).then((result) => {
        // Don't clear the form if the email was invalid or already exists
        if (result.data?.addEmail.status !== "ADDED") {
          fieldRef.current?.focus();
          fieldRef.current?.select();
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
    });
  };

  const status = addEmailResult.data?.addEmail.status ?? null;
  const emailExists = status === "EXISTS";
  const emailInvalid = status === "INVALID";
  const emailDenied = status === "DENIED";
  const violations = addEmailResult.data?.addEmail.violations ?? [];

  return (
    <>
      <Root ref={formRef} onSubmit={handleSubmit}>
        {emailExists && (
          <Alert type="info" title="Email already exists">
            The entered email is already added to this account
          </Alert>
        )}

        {emailInvalid && (
          <Alert type="critical" title="Invalid email">
            The entered email is invalid
          </Alert>
        )}

        {emailDenied && (
          <Alert type="critical" title="Email denied by policy">
            The entered email is not allowed by the server policy.
            <ul>
              {violations.map((violation, index) => (
                <li key={index}>• {violation}</li>
              ))}
            </ul>
          </Alert>
        )}

        <Field name="email" className="my-2">
          <Label>Add email</Label>
          <Control disabled={pending} inputMode="email" ref={fieldRef} />
        </Field>
        <Submit size="sm" disabled={pending}>Add</Submit>
      </Root>
    </>
  );
};

export default AddEmailForm;
