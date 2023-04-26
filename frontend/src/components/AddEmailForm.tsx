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

import React, { useRef, useTransition } from "react";
import { atomWithMutation } from "jotai-urql";
import { useAtom } from "jotai";
import { graphql } from "../gql";
import Button from "./Button";
import UserEmail from "./UserEmail";
import Input from "./Input";
import Typography from "./Typography";

const ADD_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation AddEmail($userId: ID!, $email: String!) {
    addEmail(input: { userId: $userId, email: $email }) {
      status
      user {
        id
      }
      email {
        id
        ...UserEmail_email
      }
    }
  }
`);

const addUserEmailAtom = atomWithMutation(ADD_EMAIL_MUTATION);

const AddEmailForm: React.FC<{ userId: string }> = ({ userId }) => {
  const formRef = useRef<HTMLFormElement>(null);
  const [addEmailResult, addEmail] = useAtom(addUserEmailAtom);
  const [pending, startTransition] = useTransition();

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const email = e.currentTarget.email.value;
    startTransition(() => {
      addEmail({ userId, email }).then(() => {
        if (formRef.current) {
          formRef.current.reset();
        }
      });
    });
  };

  return (
    <>
      {addEmailResult.data?.addEmail.status === "ADDED" && (
        <>
          <div className="p-4">
            <Typography variant="subtitle">Email added!</Typography>
          </div>
          <UserEmail email={addEmailResult.data?.addEmail.email} />
        </>
      )}
      {addEmailResult.data?.addEmail.status === "EXISTS" && (
        <>
          <div className="p-4">
            <Typography variant="subtitle">Email already exists!</Typography>
          </div>
          <UserEmail email={addEmailResult.data?.addEmail.email} />
        </>
      )}
      <form className="flex" onSubmit={handleSubmit} ref={formRef}>
        <Input
          className="flex-1 mr-2"
          disabled={pending}
          type="text"
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
