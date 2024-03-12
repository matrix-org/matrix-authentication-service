// Copyright 2024 Kévin Commaille.
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

//! Methods related to the account management URL.
//!
//! This is a Matrix extension introduced in [MSC2965](https://github.com/matrix-org/matrix-spec-proposals/pull/2965).

use serde::Serialize;
use serde_with::skip_serializing_none;
use url::Url;

/// An account management action that a user can take, including a device ID for
/// the actions that support it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action")]
#[non_exhaustive]
pub enum AccountManagementActionFull {
    /// `org.matrix.profile`
    ///
    /// The user wishes to view their profile (name, avatar, contact details).
    #[serde(rename = "org.matrix.profile")]
    Profile,

    /// `org.matrix.sessions_list`
    ///
    /// The user wishes to view a list of their sessions.
    #[serde(rename = "org.matrix.sessions_list")]
    SessionsList,

    /// `org.matrix.session_view`
    ///
    /// The user wishes to view the details of a specific session.
    #[serde(rename = "org.matrix.session_view")]
    SessionView {
        /// The ID of the session to view the details of.
        device_id: String,
    },

    /// `org.matrix.session_end`
    ///
    /// The user wishes to end/log out of a specific session.
    #[serde(rename = "org.matrix.session_end")]
    SessionEnd {
        /// The ID of the session to end.
        device_id: String,
    },

    /// `org.matrix.account_deactivate`
    ///
    /// The user wishes to deactivate their account.
    #[serde(rename = "org.matrix.account_deactivate")]
    AccountDeactivate,

    /// `org.matrix.cross_signing_reset`
    ///
    /// The user wishes to reset their cross-signing keys.
    #[serde(rename = "org.matrix.cross_signing_reset")]
    CrossSigningReset,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
struct AccountManagementData {
    #[serde(flatten)]
    action: Option<AccountManagementActionFull>,
    id_token_hint: Option<String>,
}

/// Build the URL for accessing the account management capabilities.
///
/// # Arguments
///
/// * `account_management_uri` - The URL to access the issuer's account
///   management capabilities.
///
/// * `action` - The action that the user wishes to take.
///
/// * `id_token_hint` - An ID Token that was previously issued to the client,
///   used as a hint for which user is requesting to manage their account.
///
/// # Returns
///
/// A URL to be opened in a web browser where the end-user will be able to
/// access the account management capabilities of the issuer.
///
/// # Errors
///
/// Returns an error if serializing the URL fails.
pub fn build_account_management_url(
    mut account_management_uri: Url,
    action: Option<AccountManagementActionFull>,
    id_token_hint: Option<String>,
) -> Result<Url, serde_urlencoded::ser::Error> {
    let data = AccountManagementData {
        action,
        id_token_hint,
    };
    let extra_query = serde_urlencoded::to_string(data)?;

    if !extra_query.is_empty() {
        // Add our parameters to the query, because the URL might already have one.
        let mut full_query = account_management_uri
            .query()
            .map(ToOwned::to_owned)
            .unwrap_or_default();

        if !full_query.is_empty() {
            full_query.push('&');
        }
        full_query.push_str(&extra_query);

        account_management_uri.set_query(Some(&full_query));
    }

    Ok(account_management_uri)
}
