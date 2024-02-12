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

import { Alert, Button, Form } from "@vector-im/compound-web";
import { useAtom } from "jotai";
import { useState, ChangeEventHandler } from "react";
import { useTranslation } from "react-i18next";
import { useMutation } from "urql";

import { graphql } from "../../gql";
import LoadingSpinner from "../LoadingSpinner/LoadingSpinner";
import { userGreetingFamily } from "../UserGreeting";

import styles from "./UserName.module.css";

const SET_DISPLAYNAME_MUTATION = graphql(/* GraphQL */ `
  mutation SetDisplayName($userId: ID!, $displayName: String) {
    setDisplayName(input: { userId: $userId, displayName: $displayName }) {
      status
      user {
        id
        matrix {
          displayName
        }
      }
    }
  }
`);

const getErrorMessage = (result: {
  error?: unknown;
  data?: { setDisplayName: { status: string } };
}): string | undefined => {
  if (result.error) {
    return "Failed to save display name. Please try again.";
  }
  if (result.data?.setDisplayName.status === "INVALID") {
    return "Failed to save invalid display name.";
  }
};

const UserName: React.FC<{ userId: string }> = ({ userId }) => {
  const [userGreeting, refreshUserGreeting] = useAtom(
    userGreetingFamily(userId),
  );
  const displayName = userGreeting.data?.user?.matrix.displayName || "";

  const [setDisplayNameResult, setDisplayName] = useMutation(
    SET_DISPLAYNAME_MUTATION,
  );

  const [hasChanges, setHasChanges] = useState(false);

  const { t } = useTranslation();

  const onChange: ChangeEventHandler<HTMLInputElement> = (event): void => {
    setHasChanges(event.target.value !== displayName);
  };

  const onSubmit = (event: React.FormEvent<HTMLFormElement>): void => {
    event.preventDefault();

    const form = event.currentTarget;
    const formData = new FormData(form);
    let newDisplayName = formData.get("displayname") as string | null;

    // set null to remove an existing username
    if (newDisplayName === "") {
      newDisplayName = null;
    }

    // do nothing if no change
    if ((!newDisplayName && !displayName) || newDisplayName === displayName) {
      return;
    }

    setDisplayName({ displayName: newDisplayName, userId }).then((result) => {
      if (!result.data) {
        console.error("Failed to set display name", result.error);
      } else if (result.data.setDisplayName.status === "SET") {
        // refresh the user greeting after changing the display name
        refreshUserGreeting({
          requestPolicy: "network-only",
        });
      } else if (result.data.setDisplayName.status === "INVALID") {
        // reset to current saved display name
        form.reset();
      }

      setHasChanges(false);
    });
  };

  const errorMessage = getErrorMessage(setDisplayNameResult);

  return (
    <Form.Root onSubmit={onSubmit} className={styles.form}>
      <Form.Field
        name="displayname"
        serverInvalid={!setDisplayNameResult.fetching && !!errorMessage}
      >
        <Form.Label>
          {t("frontend.user_name.display_name_field_label")}
        </Form.Label>
        <Form.TextControl
          defaultValue={displayName}
          onChange={onChange}
          inputMode="text"
          max={250}
        />
      </Form.Field>
      {!setDisplayNameResult.fetching && errorMessage && (
        <Alert type="critical" title={t("common.error")}>
          {errorMessage}
        </Alert>
      )}

      <Button
        className="self-start"
        disabled={setDisplayNameResult.fetching || !hasChanges}
        kind="primary"
        size="sm"
        type="submit"
      >
        {!!setDisplayNameResult.fetching && <LoadingSpinner inline />}
        {t("action.save")}
      </Button>
    </Form.Root>
  );
};

export default UserName;
