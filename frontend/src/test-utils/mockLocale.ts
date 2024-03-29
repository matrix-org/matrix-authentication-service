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

import { vi } from "vitest";

/**
 * Mock the locale on Intl.DateTimeFormat
 * To achieve stable formatted dates across environments
 * Defaults to `en-GB`
 */
export const mockLocale = (defaultLocale = "en-GB"): void => {
  const { DateTimeFormat } = Intl;
  vi.spyOn(Intl, "DateTimeFormat").mockImplementation(
    (
      locales?: Intl.LocalesArgument,
      options?: Intl.DateTimeFormatOptions | undefined,
    ) => new DateTimeFormat(locales || defaultLocale, options),
  );
};
