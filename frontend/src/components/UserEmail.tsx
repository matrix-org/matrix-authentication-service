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
  Button,
  Control,
  Field,
  Label,
  Message,
  Root as Form,
  Submit,
} from "@vector-im/compound-web";
import { atom, useAtom, useSetAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithMutation } from "jotai-urql";
import { useTransition } from "react";

import { FragmentType, graphql, useFragment } from "../gql";

import Block from "./Block";
import DateTime from "./DateTime";
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
  // TODO: compound doesn't forward the refs properly
  // const fieldRef = useRef<HTMLInputElement>(null);

  const onFormSubmit = (e: React.FormEvent<HTMLFormElement>): void => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const code = formData.get("code") as string;
    startTransition(() => {
      verifyEmail(code).then((result) => {
        // Clear the form
        e.currentTarget?.reset();

        if (result.data?.verifyEmail.status === "VERIFIED") {
          // Call the onSetPrimary callback if provided
          // XXX: do we need a dedicated onVerify callback?
          onSetPrimary?.();
        }
      });
    });
  };

  const onResendClick = (): void => {
    startTransition(() => {
      resendVerificationEmail().then(() => {
        // TODO: fieldRef.current?.focus();
      });
    });
  };

  const onRemoveClick = (): void => {
    startTransition(() => {
      removeEmail().then(() => {
        // Call the onRemove callback if provided
        onRemove?.();
      });
    });
  };

  const onSetPrimaryClick = (): void => {
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
    <Block
      highlight={highlight}
      className="grid grid-col-1 gap-2 pb-4 border-b-2 border-b-grey-200"
    >
      {isPrimary && (
        <Typography variant="body" bold>
          Primary
        </Typography>
      )}
      <Typography variant="caption" bold className="flex-1">
        {data.email}
      </Typography>
      {data.confirmedAt ? (
        <Typography variant="micro">
          Verified <DateTime datetime={data.confirmedAt} />
        </Typography>
      ) : (
        <Form onSubmit={onFormSubmit} className="grid grid-cols-2 gap-2">
          <Field name="code" className="col-span-2">
            <Label>Code</Label>
            <Control
              // ref={fieldRef}
              placeholder="xxxxxx"
              type="text"
              inputMode="numeric"
            />
          </Field>
          {invalidCode && (
            <Message className="col-span-2 text-alert font-bold">
              Invalid code
            </Message>
          )}
          <Submit size="sm" type="submit" disabled={pending}>
            Submit
          </Submit>
          <Button
            size="sm"
            kind="secondary"
            disabled={pending || emailSent}
            onClick={onResendClick}
          >
            {emailSent ? "Sent!" : "Resend"}
          </Button>
        </Form>
      )}
      {!isPrimary && (
        <div className="flex justify-between items-center">
          {/* The primary email can only be set if the email was verified */}
          {data.confirmedAt ? (
            <Button size="sm" disabled={pending} onClick={onSetPrimaryClick}>
              Set primary
            </Button>
          ) : (
            <div />
          )}
          <Button
            kind="destructive"
            size="sm"
            disabled={pending}
            onClick={onRemoveClick}
          >
            Remove
          </Button>
        </div>
      )}
    </Block>
  );
};

export default UserEmail;
