// Copyright 2024 The Matrix.org Foundation C.I.C.
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

import { Form, Progress } from "@vector-im/compound-web";
import { useDeferredValue, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { FragmentType, graphql, useFragment } from "../gql";
import {
  PasswordComplexity,
  estimatePasswordComplexity,
} from "../utils/password_complexity";

const CONFIG_FRAGMENT = graphql(/* GraphQL */ `
  fragment PasswordCreationDoubleInput_siteConfig on SiteConfig {
    id
    minimumPasswordComplexity
  }
`);

const usePasswordComplexity = (password: string): PasswordComplexity => {
  const { t } = useTranslation();
  const [result, setResult] = useState<PasswordComplexity>({
    score: 0,
    scoreText: t("frontend.password_strength.placeholder"),
    improvementsText: [],
  });
  const deferredPassword = useDeferredValue(password);

  useEffect(() => {
    if (deferredPassword === "") {
      setResult({
        score: 0,
        scoreText: t("frontend.password_strength.placeholder"),
        improvementsText: [],
      });
    } else {
      estimatePasswordComplexity(deferredPassword, t).then((response) =>
        setResult(response),
      );
    }
  }, [deferredPassword, t]);

  return result;
};

export default function PasswordCreationDoubleInput({
  siteConfig,
  forceShowNewPasswordInvalid,
}: {
  siteConfig: FragmentType<typeof CONFIG_FRAGMENT>;
  forceShowNewPasswordInvalid: boolean;
}): React.ReactElement {
  const { t } = useTranslation();
  const { minimumPasswordComplexity } = useFragment(
    CONFIG_FRAGMENT,
    siteConfig,
  );

  const newPasswordRef = useRef<HTMLInputElement>(null);
  const newPasswordAgainRef = useRef<HTMLInputElement>(null);
  const [newPassword, setNewPassword] = useState("");

  const passwordComplexity = usePasswordComplexity(newPassword);
  let passwordStrengthTint;
  if (newPassword === "") {
    passwordStrengthTint = undefined;
  } else {
    passwordStrengthTint = ["red", "red", "orange", "lime", "green"][
      passwordComplexity.score
    ] as "red" | "orange" | "lime" | "green" | undefined;
  }

  return (
    <>
      <Form.Field name="new_password">
        <Form.Label>
          {t("frontend.password_change.new_password_label")}
        </Form.Label>

        <Form.PasswordControl
          required
          autoComplete="new-password"
          ref={newPasswordRef}
          onBlur={() =>
            newPasswordAgainRef.current!.value &&
            newPasswordAgainRef.current!.reportValidity()
          }
          onChange={(e) => setNewPassword(e.target.value)}
        />

        <Progress
          size="sm"
          getValueLabel={() => passwordComplexity.scoreText}
          tint={passwordStrengthTint}
          max={4}
          value={passwordComplexity.score}
        />

        {passwordComplexity.improvementsText.map((suggestion) => (
          <Form.HelpMessage>{suggestion}</Form.HelpMessage>
        ))}

        {passwordComplexity.score < minimumPasswordComplexity && (
          <Form.ErrorMessage match={() => true}>
            {t("frontend.password_strength.too_weak")}
          </Form.ErrorMessage>
        )}

        <Form.ErrorMessage match="valueMissing">
          {t("frontend.errors.field_required")}
        </Form.ErrorMessage>

        {forceShowNewPasswordInvalid && (
          <Form.ErrorMessage>
            {t(
              "frontend.password_change.failure.description.invalid_new_password",
            )}
          </Form.ErrorMessage>
        )}
      </Form.Field>

      <Form.Field name="new_password_again">
        {/*
        TODO This field has validation defects,
        some caused by Radix-UI upstream bugs.
        https://github.com/matrix-org/matrix-authentication-service/issues/2855
      */}
        <Form.Label>
          {t("frontend.password_change.new_password_again_label")}
        </Form.Label>

        <Form.PasswordControl
          required
          ref={newPasswordAgainRef}
          autoComplete="new-password"
        />

        <Form.ErrorMessage match="valueMissing">
          {t("frontend.errors.field_required")}
        </Form.ErrorMessage>

        <Form.ErrorMessage match={(v, form) => v !== form.get("new_password")}>
          {t("frontend.password_change.passwords_no_match")}
        </Form.ErrorMessage>

        <Form.SuccessMessage match="valid">
          {t("frontend.password_change.passwords_match")}
        </Form.SuccessMessage>
      </Form.Field>
    </>
  );
}
