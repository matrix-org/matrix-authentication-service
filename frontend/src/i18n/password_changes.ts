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

import { TFunction } from "i18next";

import { SetPasswordStatus } from "../gql/graphql";

/**
 * Provides a translated string representing a `SetPasswordStatus`.
 *
 * Returns the translated string, or undefined if a translated string is not shown at the
 * top-level of a password change form for this status.
 *
 * The form is responsible for showing the following errors itself, inline with the form field:
 * - `WrongPassword`
 * - `InvalidNewPassword`
 *
 * Throws an error if the status is not known.
 */
export function translateSetPasswordError(
  t: TFunction<"frontend", undefined>,
  status: SetPasswordStatus | undefined,
): string | undefined {
  switch (status) {
    case SetPasswordStatus.NoCurrentPassword:
      return t(
        "frontend.password_change.failure.description.no_current_password",
      );
    case SetPasswordStatus.PasswordChangesDisabled:
      return t(
        "frontend.password_change.failure.description.password_changes_disabled",
      );
    case SetPasswordStatus.AccountLocked:
      return t("frontend.password_change.failure.description.account_locked");
    case SetPasswordStatus.ExpiredRecoveryTicket:
      return t(
        "frontend.password_change.failure.description.expired_recovery_ticket",
      );
    case SetPasswordStatus.NoSuchRecoveryTicket:
      return t(
        "frontend.password_change.failure.description.no_such_recovery_ticket",
      );
    case SetPasswordStatus.RecoveryTicketAlreadyUsed:
      return t(
        "frontend.password_change.failure.description.recovery_ticket_already_used",
      );

    case SetPasswordStatus.WrongPassword:
    case SetPasswordStatus.InvalidNewPassword:
      // These cases are shown as inline errors in the form itself.
      return undefined;

    case SetPasswordStatus.Allowed:
    case undefined:
      return undefined;

    default:
      throw new Error(`unexpected error when changing password: ${status}`);
  }
}
