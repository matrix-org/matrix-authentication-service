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

import { CombinedError } from "@urql/core";
import { useAtomValue } from "jotai";

import { currentBrowserSessionIdAtom } from "../../atoms";
import { isOk, unwrapOk, unwrapErr, isErr } from "../../result";

/**
 * Query the current browser session id
 * and unwrap the result
 * throws error when error result
 */
export const useCurrentBrowserSessionId = (): string | null => {
  const currentSessionIdResult = useAtomValue(currentBrowserSessionIdAtom);

  if (isErr(currentSessionIdResult)) {
    // eslint-disable-next-line no-throw-literal
    throw unwrapErr<CombinedError>(currentSessionIdResult) as Error;
  }

  if (isOk<string | null, unknown>(currentSessionIdResult)) {
    return unwrapOk<string | null>(currentSessionIdResult);
  }

  return null;
};
