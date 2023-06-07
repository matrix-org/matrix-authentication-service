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
import { atom, useAtom, useSetAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithMutation } from "jotai-urql";
import { useRef, useTransition } from "react";

import { FragmentType, graphql, useFragment } from "../gql";

import Block from "./Block";
import DateTime from "./DateTime";
import Input from "./Input";
import Typography from "./Typography";

// This component shows a single user email address, with controls to verify it,
// resend the verification email, remove it, and set it as the primary email address.

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

const removeEmailFamily = atomFamily((id: string) => {
  const removeEmail = atomWithMutation(REMOVE_EMAIL_MUTATION);

  // A proxy atom which pre-sets the id variable in the mutation
  const removeEmailAtom = atom(
    (get) => get(removeEmail),
    (get, set) => set(removeEmail, { id })
  );

  return removeEmailAtom;
});

const setPrimaryEmailFamily = atomFamily((id: string) => {
  const setPrimaryEmail = atomWithMutation(SET_PRIMARY_EMAIL_MUTATION);

  // A proxy atom which pre-sets the id variable in the mutation
  const setPrimaryEmailAtom = atom(
    (get) => get(setPrimaryEmail),
    (get, set) => set(setPrimaryEmail, { id })
  );

  return setPrimaryEmailAtom;
});

const UserEmail: React.FC<{
  email: FragmentType<typeof FRAGMENT>;
  onRemove?: () => void;
  onSetPrimary?: () => void;
  isPrimary?: boolean;
  highlight?: boolean;
}> = ({ email, isPrimary, highlight, onSetPrimary, onRemove }) => {
  const [pending, startTransition] = useTransition();
  const data = useFragment(FRAGMENT, email);
  const [verifyEmailResult, verifyEmail] = useAtom(verifyEmailFamily(data.id));
  const [resendVerificationEmailResult, resendVerificationEmail] = useAtom(
    resendVerificationEmailFamily(data.id)
  );
  const setPrimaryEmail = useSetAtom(setPrimaryEmailFamily(data.id));
  const removeEmail = useSetAtom(removeEmailFamily(data.id));
  const formRef = useRef<HTMLFormElement>(null);

  const onFormSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const code = formData.get("code") as string;
    startTransition(() => {
      verifyEmail(code).then((result) => {
        // Clear the form
        formRef.current?.reset();

        if (result.data?.verifyEmail.status === "VERIFIED") {
          // Call the onSetPrimary callback if provided
          // XXX: do we need a dedicated onVerify callback?
          onSetPrimary?.();
        }
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

  const onRemoveClick = () => {
    startTransition(() => {
      removeEmail().then(() => {
        // Call the onRemove callback if provided
        onRemove?.();
      });
    });
  };

  const onSetPrimaryClick = () => {
    startTransition(() => {
      setPrimaryEmail().then(() => {
        // Call the onSetPrimary callback if provided
        onSetPrimary?.();
      });
    });
  };

  const emailSent =
    resendVerificationEmailResult.data?.sendVerificationEmail.status === "SENT";
  const invalidCode =
    verifyEmailResult.data?.verifyEmail.status === "INVALID_CODE";

  return (
    <Block highlight={highlight}>
      {isPrimary && (
        <Typography variant="body" bold>
          Primary
        </Typography>
      )}
      <div className="flex justify-between items-center">
        <Typography variant="caption" bold className="flex-1">
          {data.email}
        </Typography>
        {!isPrimary && (
          <>
            {/* The primary email can only be set if the email was verified */}
            {data.confirmedAt && (
              <Button
                disabled={pending}
                onClick={onSetPrimaryClick}
                className="ml-2"
              >
                Set primary
              </Button>
            )}
            <Button disabled={pending} onClick={onRemoveClick} className="ml-2">
              Remove
            </Button>
          </>
        )}
      </div>
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
          {invalidCode && (
            <div className="col-span-2 text-alert font-bold">Invalid code</div>
          )}
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
