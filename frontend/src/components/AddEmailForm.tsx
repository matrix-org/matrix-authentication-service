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

import { Button } from "@vector-im/compound-web";
import { atom, useAtom } from "jotai";
import { atomWithMutation } from "jotai-urql";
import { useRef, useTransition } from "react";

import { graphql } from "../gql";

import Input from "./Input";
import Typography from "./Typography";

const ADD_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation AddEmail($userId: ID!, $email: String!) {
    addEmail(input: { userId: $userId, email: $email }) {
      status
      email {
        id
        ...UserEmail_email
      }
    }
  }
`);

const addUserEmailAtom = atomWithMutation(ADD_EMAIL_MUTATION);

export const latestAddedEmailAtom = atom(async (get) => {
  const result = await get(addUserEmailAtom);
  return result.data?.addEmail.email?.id ?? null;
});

const AddEmailForm: React.FC<{ userId: string; onAdd?: () => void }> = ({
  userId,
  onAdd,
}) => {
  const formRef = useRef<HTMLFormElement>(null);
  const [addEmailResult, addEmail] = useAtom(addUserEmailAtom);
  const [pending, startTransition] = useTransition();

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>): void => {
    e.preventDefault();

    const formData = new FormData(e.currentTarget);
    const email = formData.get("email") as string;
    startTransition(() => {
      addEmail({ userId, email }).then((result) => {
        // Don't clear the form if the email was invalid
        if (result.data?.addEmail.status === "INVALID") {
          return;
        }

        // Call the onAdd callback if provided
        onAdd?.();

        // Reset the form
        formRef.current?.reset();
      });
    });
  };

  const status = addEmailResult.data?.addEmail.status ?? null;
  const emailAdded = status === "ADDED";
  const emailExists = status === "EXISTS";
  const emailInvalid = status === "INVALID";

  return (
    <>
      {emailAdded && (
        <div className="pt-4">
          <Typography variant="subtitle">Email added!</Typography>
        </div>
      )}

      {emailExists && (
        <div className="pt-4">
          <Typography variant="subtitle">Email already exists!</Typography>
        </div>
      )}

      {emailInvalid && (
        <div className="pt-4 text-alert">
          <Typography variant="subtitle" bold>
            Invalid email address
          </Typography>
        </div>
      )}

      <form className="flex" onSubmit={handleSubmit} ref={formRef}>
        <Input
          className="flex-1 mr-2"
          disabled={pending}
          type="email"
          inputMode="email"
          name="email"
        />
        <Button kind="primary" disabled={pending} type="submit">
          Add
        </Button>
      </form>
    </>
  );
};

export default AddEmailForm;
