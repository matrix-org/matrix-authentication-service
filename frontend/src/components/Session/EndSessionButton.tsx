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
import { useState } from "react";

import ConfirmationModal from "../ConfirmationModal/ConfirmationModal";
import LoadingSpinner from "../LoadingSpinner/LoadingSpinner";

/**
 * Generic end session button
 * Launches a confirmation modal on click
 * Handles loading state while endSession is in progress
 */
const EndSessionButton: React.FC<{
  endSession: () => Promise<void>;
  /**
   * The number of sessions that will be ended
   * When falsy, ONE is used as default
   */
  sessionCount?: number;
}> = ({ endSession, sessionCount }) => {
  const [inProgress, setInProgress] = useState(false);

  const onConfirm = async (): Promise<void> => {
    setInProgress(true);
    try {
      await endSession();
    } catch (error) {
      console.error("Failed to end session", error);
    }
    setInProgress(false);
  };

  // NOOP so we render cancel button
  const onDeny = (): void => {};

  const title =
    sessionCount && sessionCount > 1
      ? `Are you sure you want to end ${sessionCount} sessions?`
      : "Are you sure you want to end this session?";
  const buttonLabel =
    sessionCount && sessionCount > 1
      ? `End ${sessionCount} sessions`
      : "End session";

  return (
    <>
      <ConfirmationModal
        onDeny={onDeny}
        onConfirm={onConfirm}
        title={title}
        trigger={
          <Button kind="destructive" size="sm" disabled={inProgress}>
            {inProgress && <LoadingSpinner inline />}
            {buttonLabel}
          </Button>
        }
      />
    </>
  );
};

export default EndSessionButton;
