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

import { atom, useAtom, useSetAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithMutation } from "jotai-urql";
import { useRef, useTransition } from "react";

import { FragmentType, graphql, useFragment } from "../gql";

import Block from "./Block";
import Button from "./Button";
import DateTime from "./DateTime";
import Input from "./Input";
import Typography, { Bold } from "./Typography";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment UserEmail_email on UserEmail {
    id
    email
    createdAt
    confirmedAt
  }
`);

const VERIFY_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation VerifyEmail($id: ID!, $code: String!) {
    verifyEmail(input: { userEmailId: $id, code: $code }) {
      status

      user {
        id
        primaryEmail {
          id
        }
      }

      email {
        id
        ...UserEmail_email
      }
    }
  }
`);

const RESEND_VERIFICATION_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation ResendVerificationEmail($id: ID!) {
    sendVerificationEmail(input: { userEmailId: $id }) {
      status

      user {
        id
        primaryEmail {
          id
        }
      }

      email {
        id
        ...UserEmail_email
      }
    }
  }
`);

const verifyEmailFamily = atomFamily((id: string) => {
  const verifyEmail = atomWithMutation(VERIFY_EMAIL_MUTATION);

  // A proxy atom which pre-sets the id variable in the mutation
  const verifyEmailAtom = atom(
    (get) => get(verifyEmail),
    (get, set, code: string) => set(verifyEmail, { id, code })
  );

  return verifyEmailAtom;
});

const resendVerificationEmailFamily = atomFamily((id: string) => {
  const resendVerificationEmail = atomWithMutation(
    RESEND_VERIFICATION_EMAIL_MUTATION
  );

  // A proxy atom which pre-sets the id variable in the mutation
  const resendVerificationEmailAtom = atom(
    (get) => get(resendVerificationEmail),
    (get, set) => set(resendVerificationEmail, { id })
  );

  return resendVerificationEmailAtom;
});

const UserEmail: React.FC<{
  email: FragmentType<typeof FRAGMENT>;
  isPrimary?: boolean;
  highlight?: boolean;
}> = ({ email, isPrimary, highlight }) => {
  const [pending, startTransition] = useTransition();
  const data = useFragment(FRAGMENT, email);
  const [verifyEmailResult, verifyEmail] = useAtom(verifyEmailFamily(data.id));
  const [resendVerificationEmailResult, resendVerificationEmail] = useAtom(
    resendVerificationEmailFamily(data.id)
  );
  const formRef = useRef<HTMLFormElement>(null);

  const onFormSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const code = formData.get("code") as string;
    startTransition(() => {
      verifyEmail(code).then(() => {
        formRef.current?.reset();
      });
    });
  };

  const onResendClick = () => {
    startTransition(() => {
      resendVerificationEmail().then(() => {
        formRef.current?.code.focus();
      });
    });
  };

  const emailSent =
    resendVerificationEmailResult.data?.sendVerificationEmail.status === "SENT";

  return (
    <Block highlight={highlight}>
      {isPrimary && (
        <Typography variant="body" bold>
          Primary
        </Typography>
      )}
      <Typography variant="caption">
        <Bold>{data.email}</Bold>
      </Typography>
      {data.confirmedAt ? (
        <Typography variant="micro">
          Verified <DateTime datetime={data.confirmedAt} />
        </Typography>
      ) : (
        <form
          onSubmit={onFormSubmit}
          className="mt-2 grid grid-cols-2 gap-2"
          ref={formRef}
        >
          <Input
            className="col-span-2"
            name="code"
            placeholder="Code"
            type="text"
            inputMode="numeric"
          />
          <Button type="submit" disabled={pending}>
            Submit
          </Button>
          <Button disabled={pending || emailSent} onClick={onResendClick}>
            {emailSent ? "Sent!" : "Resend"}
          </Button>
        </form>
      )}
    </Block>
  );
};

export default UserEmail;
