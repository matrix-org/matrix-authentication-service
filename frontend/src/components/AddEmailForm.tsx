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

import { useAtom, useSetAtom } from "jotai";
import { atomWithMutation } from "jotai-urql";
import { useRef, useTransition } from "react";

import { graphql } from "../gql";
import { LAST_PAGE } from "../pagination";

import Button from "./Button";
import Input from "./Input";
import Typography from "./Typography";
import {
  currentPaginationAtom,
  emailPageResultFamily,
  primaryEmailResultFamily,
} from "./UserEmailList";

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

export const addUserEmailAtom = atomWithMutation(ADD_EMAIL_MUTATION);

const AddEmailForm: React.FC<{ userId: string }> = ({ userId }) => {
  const formRef = useRef<HTMLFormElement>(null);
  const [addEmailResult, addEmail] = useAtom(addUserEmailAtom);
  const [pending, startTransition] = useTransition();

  // XXX: is this the right way to do this?
  const refetchList = useSetAtom(emailPageResultFamily(userId));
  const refetchPrimaryEmail = useSetAtom(primaryEmailResultFamily(userId));
  const setCurrentPagination = useSetAtom(currentPaginationAtom);

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    const formData = new FormData(e.currentTarget);
    const email = formData.get("email") as string;
    startTransition(() => {
      addEmail({ userId, email }).then(() => {
        startTransition(() => {
          // Paginate to the last page
          setCurrentPagination(LAST_PAGE);

          // Make it refetch the list and the primary email, in case they changed
          refetchList();
          refetchPrimaryEmail();

          // Reset the form
          formRef.current?.reset();
        });
      });
    });
  };

  return (
    <>
      {addEmailResult.data?.addEmail.status === "ADDED" && (
        <>
          <div className="pt-4">
            <Typography variant="subtitle">Email added!</Typography>
          </div>
        </>
      )}
      {addEmailResult.data?.addEmail.status === "EXISTS" && (
        <>
          <div className="pt-4">
            <Typography variant="subtitle">Email already exists!</Typography>
          </div>
        </>
      )}
      <form className="flex" onSubmit={handleSubmit} ref={formRef}>
        <Input
          className="flex-1 mr-2"
          disabled={pending}
          type="email"
          inputMode="email"
          name="email"
        />
        <Button disabled={pending} type="submit">
          Add
        </Button>
      </form>
    </>
  );
};

export default AddEmailForm;
