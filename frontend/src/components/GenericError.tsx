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

import IconError from "@vector-im/compound-design-tokens/assets/web/icons/error";
import { Button } from "@vector-im/compound-web";
import { useState } from "react";
import { Translation } from "react-i18next";

import BlockList from "./BlockList";
import styles from "./GenericError.module.css";
import PageHeading from "./PageHeading";

const GenericError: React.FC<{ error: unknown; dontSuspend?: boolean }> = ({
  error,
  dontSuspend,
}) => {
  const [open, setOpen] = useState(false);
  return (
    <Translation useSuspense={!dontSuspend}>
      {(t) => (
        <BlockList>
          <PageHeading
            invalid
            Icon={IconError}
            title={t("frontend.error.title", {
              defaultValue: "Something went wrong",
            })}
            subtitle={t("frontend.error.subtitle", {
              defaultValue: "An unexpected error occured. Please try again.",
            })}
          />
          <Button kind="tertiary" onClick={() => setOpen(!open)}>
            {open
              ? t("frontend.error.hideDetails", {
                  defaultValue: "Hide details",
                })
              : t("frontend.error.showDetails", {
                  defaultValue: "Show details",
                })}
          </Button>
          {open && (
            <pre className={styles.details}>
              <code>{String(error)}</code>
            </pre>
          )}
        </BlockList>
      )}
    </Translation>
  );
};

export default GenericError;
