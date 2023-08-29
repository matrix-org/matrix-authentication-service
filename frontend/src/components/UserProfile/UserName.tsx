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
import { useAtomValue, useAtom, useSetAtom, atom } from "jotai";
import { atomFamily } from "jotai/utils";
import { atomWithMutation } from "jotai-urql";
import { useState, useEffect, useRef } from "react";

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

const setDisplayNameFamily = atomFamily((userId: string) => {
  const setDisplayName = atomWithMutation(SET_DISPLAYNAME_MUTATION);

  // A proxy atom which pre-sets the id variable in the mutation
  const setDisplayNameAtom = atom(
    (get) => get(setDisplayName),
    (get, set, displayName: string | null) =>
      set(setDisplayName, { userId, displayName }),
  );

  return setDisplayNameAtom;
});

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
  const fieldRef = useRef<HTMLInputElement>(null);

  const [setDisplayNameResult, setDisplayName] = useAtom(
    setDisplayNameFamily(userId),
  );
  const [inProgress, setInProgress] = useState(false);

  const user = result.data?.user;
  const displayName = user?.matrix.displayName || "";

  const userGreeting = useSetAtom(userGreetingFamily(userId));

  useEffect(() => {
    if (fieldRef.current) {
      fieldRef.current.value = displayName;
    }
  }, [displayName]);

  const onSubmit = (event: React.FormEvent<HTMLFormElement>): void => {
    event.preventDefault();

    const formData = new FormData(event.currentTarget);
    let newDisplayName = (formData.get("displayname") as string) || null;

    // set null to remove an existing username
    if (newDisplayName === "") {
      newDisplayName = null;
    }

    // do nothing if no change
    if ((!newDisplayName && !displayName) || newDisplayName === displayName) {
      return;
    }

    setInProgress(true);
    setDisplayName(newDisplayName).then((result) => {
      if (!result.data) {
        console.error("Failed to set display name", result.error);
      } else if (result.data.setDisplayName.status === "SET") {
        // refresh the user greeting after changing the display name
        userGreeting({
          requestPolicy: "network-only",
        });
      } else if (result.data.setDisplayName.status === "INVALID") {
        // reset to current saved display name
        if (fieldRef.current) {
          fieldRef.current.value = displayName;
        }
      }
      setInProgress(false);
    });
  };

  const errorMessage = getErrorMessage(setDisplayNameResult);

  return (
    <Root onSubmit={onSubmit} className={styles.form}>
      <Field name="displayname">
        <Label>Display Name</Label>
        <Control ref={fieldRef} inputMode="text" max={250} />
      </Field>
      {!inProgress && errorMessage && (
        <Alert type="critical" title="Error">
          {errorMessage}
        </Alert>
      )}

      <Button
        className={styles.saveButton}
        disabled={inProgress}
        kind="primary"
        size="sm"
        type="submit"
      >
        {!!inProgress && <LoadingSpinner inline />}Save
      </Button>
    </Root>
  );
};

export default UserName;
