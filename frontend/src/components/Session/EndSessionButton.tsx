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

import { Body, Button } from "@vector-im/compound-web";
import { useState } from "react";

import ConfirmationModal from "../ConfirmationModal/ConfirmationModal";
import LoadingSpinner from "../LoadingSpinner/LoadingSpinner";

/**
 * Generic end session button
 * Handles loading state while endSession is in progress
 */
const EndSessionButton: React.FC<{ endSession: () => Promise<void> }> = ({
  endSession,
}) => {
  const [inProgress, setInProgress] = useState(false);
  const [isConfirming, setIsConfirming] = useState(false);

  const onClick = (): void => {
    setIsConfirming(true);
  };

  const onConfirm = async (): Promise<void> => {
    setInProgress(true);
    setIsConfirming(false);
    try {
      await endSession();
    } catch (error) {
      console.error("Failed to end session", error);
    }
    setInProgress(false);
  };

  const onDeny = (): void => setIsConfirming(false);

  return (
    <>
      <Button
        kind="destructive"
        size="sm"
        onClick={onClick}
        disabled={inProgress}
      >
        {inProgress && <LoadingSpinner inline />}End session
      </Button>
      {isConfirming && (
        <ConfirmationModal
          isOpen={isConfirming}
          onRequestClose={onDeny}
          buttons={
            <>
              <Button kind="tertiary" size="sm" onClick={onDeny}>
                Cancel
              </Button>
              <Button kind="destructive" size="sm" onClick={onConfirm}>
                Continue
              </Button>
            </>
          }
        >
          <Body>Are you sure you want to end this session?</Body>
        </ConfirmationModal>
      )}
    </>
  );
};

export default EndSessionButton;
