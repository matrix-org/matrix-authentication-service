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
  Button,
} from "@vector-im/compound-web";
import { useAtomValue, useAtom, useSetAtom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithQuery, atomWithMutation } from "jotai-urql";
import {
  useState,
  useEffect,
  ChangeEventHandler,
  FormEventHandler,
} from "react";

import { graphql } from "../../gql";
import LoadingSpinner from "../LoadingSpinner/LoadingSpinner";

import styles from "./UserName.module.css";

const QUERY = graphql(/* GraphQL */ `
  query UserGreeting($userId: ID!) {
    user(id: $userId) {
      id
      username
      matrix {
        mxid
        displayName
      }
    }
  }
`);

const userGreetingFamily = atomFamily((userId: string) => {
  const userGreeting = atomWithQuery({
    query: QUERY,
    getVariables: () => ({ userId }),
  });

  return userGreeting;
});

const SET_DISPLAYNAME_MUTATION = graphql(/* GraphQL */ `
  mutation SetDisplayName($userId: ID!, $displayName: String!) {
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

const setDisplayNameAtom = atomWithMutation(SET_DISPLAYNAME_MUTATION);

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
  const result = useAtomValue(userGreetingFamily(userId));

  const [setDisplayNameResult, setDisplayName] = useAtom(setDisplayNameAtom);
  const [inProgress, setInProgress] = useState(false);

  const user = result.data?.user;
  const displayName = user?.matrix.displayName || "";

  const [editingDisplayName, setEditingDisplayName] = useState(displayName);

  const userGreeting = useSetAtom(userGreetingFamily(userId));

  useEffect(() => {
    setEditingDisplayName(displayName);
  }, [displayName]);

  const onDisplayNameChange: ChangeEventHandler<HTMLInputElement> = (
    event,
  ): void => {
    setEditingDisplayName(event.target.value);
  };

  const onSubmit: FormEventHandler<HTMLButtonElement | HTMLFormElement> = (
    event,
  ) => {
    event.preventDefault();

    let newDisplayName = editingDisplayName;

    // set null to remove an existing username
    if (editingDisplayName === "") {
      newDisplayName = "";
    }

    // do nothing if no change
    if (
      (!editingDisplayName && !displayName) ||
      editingDisplayName === displayName
    ) {
      return;
    }

    setInProgress(true);
    setDisplayName({ userId, displayName: newDisplayName }).then((result) => {
      if (!result.data) {
        console.error("Failed to set display name", result.error);
      } else if (result.data.setDisplayName.status === "SET") {
        // refresh the user greeting after changing the display name
        userGreeting({
          requestPolicy: "network-only",
        });
      } else if (result.data.setDisplayName.status === "INVALID") {
        // reset to current saved display name
        setEditingDisplayName(displayName);
      }
      setInProgress(false);
    });
  };

  const errorMessage = getErrorMessage(setDisplayNameResult);

  return (
    <Root onSubmit={onSubmit} method="POST" className={styles.form}>
      <Field name="displayname" className={styles.input}>
        <Label>Display Name</Label>
        <Control
          inputMode="text"
          max={250}
          value={editingDisplayName}
          onChange={onDisplayNameChange}
        />
      </Field>
      {!inProgress && errorMessage && (
        <Alert type="critical" title="Error">
          {errorMessage}
        </Alert>
      )}

      <Button disabled={inProgress} onClick={onSubmit} kind="primary" size="sm">
        {!!inProgress && <LoadingSpinner inline />}Save
      </Button>
    </Root>
  );
};

export default UserName;
