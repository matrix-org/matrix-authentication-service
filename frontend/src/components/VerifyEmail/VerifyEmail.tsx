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

import IconArrowLeft from "@vector-im/compound-design-tokens/icons/arrow-left.svg?react";
import IconSend from "@vector-im/compound-design-tokens/icons/check.svg?react";
import {
  Button,
  Control,
  Field,
  Label,
  Submit,
  Root as Form,
  Alert,
  H1,
  Text,
} from "@vector-im/compound-web";
import { useSetAtom, atom, useAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithMutation } from "jotai-urql";
import { useEffect, useRef, useTransition } from "react";
import { Trans, useTranslation } from "react-i18next";

import { FragmentType, graphql, useFragment } from "../../gql";
import { routeAtom, useNavigationLink } from "../../routing";

import styles from "./VerifyEmail.module.css";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment UserEmail_verifyEmail on UserEmail {
    id
    email
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
    (get, set, code: string) => set(verifyEmail, { id, code }),
  );

  return verifyEmailAtom;
});

const resendVerificationEmailFamily = atomFamily((id: string) => {
  const resendVerificationEmail = atomWithMutation(
    RESEND_VERIFICATION_EMAIL_MUTATION,
  );

  // A proxy atom which pre-sets the id variable in the mutation
  const resendVerificationEmailAtom = atom(
    (get) => get(resendVerificationEmail),
    (_get, set) => set(resendVerificationEmail, { id }),
  );

  return resendVerificationEmailAtom;
});

const BackButton: React.FC = () => {
  const { onClick, href, pending } = useNavigationLink({
    type: "profile",
  });

  return (
    <Button
      as="a"
      href={href}
      onClick={onClick}
      Icon={IconArrowLeft}
      kind="tertiary"
    >
      {pending ? "Loading..." : "Back"}
    </Button>
  );
};

const VerifyEmail: React.FC<{
  email: FragmentType<typeof FRAGMENT>;
}> = ({ email }) => {
  const data = useFragment(FRAGMENT, email);
  const [pending, startTransition] = useTransition();
  const [verifyEmailResult, verifyEmail] = useAtom(verifyEmailFamily(data.id));
  const [resendVerificationEmailResult, resendVerificationEmail] = useAtom(
    resendVerificationEmailFamily(data.id),
  );
  const setRoute = useSetAtom(routeAtom);
  const fieldRef = useRef<HTMLInputElement>(null);
  const { t } = useTranslation();

  const onFormSubmit = (e: React.FormEvent<HTMLFormElement>): void => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const code = formData.get("code") as string;
    startTransition(() => {
      verifyEmail(code).then((result) => {
        // Clear the form
        e.currentTarget?.reset();

        if (result.data?.verifyEmail.status === "VERIFIED") {
          setRoute({ type: "profile" });
        } else {
          fieldRef.current?.focus();
          fieldRef.current?.select();
        }
      });
    });
  };

  // Focus the field on mount
  useEffect(() => {
    fieldRef.current?.focus();
  }, [fieldRef]);

  const onResendClick = (): void => {
    startTransition(() => {
      resendVerificationEmail().then(() => {
        fieldRef.current?.focus();
      });
    });
  };

  const emailSent =
    resendVerificationEmailResult.data?.sendVerificationEmail.status === "SENT";
  const invalidCode =
    verifyEmailResult.data?.verifyEmail.status === "INVALID_CODE";
  const { email: codeEmail } = data;

  return (
    <div className={styles.block}>
      <header className={styles.header}>
        <IconSend className={styles.icon} />
        <H1>{t("frontend.verify_email.heading")}</H1>
        <Text size="lg" className={styles.tagline}>
          <Trans i18nKey="frontend.verify_email.enter_code_prompt">
            Enter the 6-digit code sent to{" "}
            <Text as="span" size="lg" weight="semibold">
              {{ codeEmail }}
            </Text>
          </Trans>
        </Text>
      </header>

      <Form onSubmit={onFormSubmit} className={styles.form}>
        {invalidCode && (
          <Alert
            type="critical"
            title={t("frontend.verify_email.invalid_code_alert")}
          />
        )}
        <Field name="code" serverInvalid={invalidCode}>
          <Label>{t("frontend.verify_email.code_field_label")}</Label>
          <Control
            ref={fieldRef}
            placeholder="xxxxxx"
            type="text"
            inputMode="numeric"
          />
        </Field>

        <Submit
          type="submit"
          disabled={pending}
          className={styles.submitButton}
        >
          {t("action.continue")}
        </Submit>
        <Button
          kind="secondary"
          disabled={pending || emailSent}
          onClick={onResendClick}
        >
          {emailSent ? "Sent!" : "Resend email"}
        </Button>
        <BackButton />
      </Form>
    </div>
  );
};

export default VerifyEmail;
