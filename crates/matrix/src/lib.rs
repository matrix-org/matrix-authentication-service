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

mod mock;

pub use self::mock::HomeserverConnection as MockHomeserverConnection;

#[derive(Debug)]
pub struct MatrixUser {
    pub displayname: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Default)]
enum FieldAction<T> {
    #[default]
    DoNothing,
    Set(T),
    Unset,
}

pub struct ProvisionRequest {
    mxid: String,
    sub: String,
    displayname: FieldAction<String>,
    avatar_url: FieldAction<String>,
    emails: FieldAction<Vec<String>>,
}

impl ProvisionRequest {
    /// Create a new [`ProvisionRequest`].
    ///
    /// # Parameters
    ///
    /// * `mxid` - The Matrix ID to provision.
    /// * `sub` - The `sub` of the user, aka the internal ID.
    #[must_use]
    pub fn new(mxid: impl Into<String>, sub: impl Into<String>) -> Self {
        Self {
            mxid: mxid.into(),
            sub: sub.into(),
            displayname: FieldAction::DoNothing,
            avatar_url: FieldAction::DoNothing,
            emails: FieldAction::DoNothing,
        }
    }

    /// Get the `sub` of the user to provision, aka the internal ID.
    #[must_use]
    pub fn sub(&self) -> &str {
        &self.sub
    }

    /// Get the Matrix ID to provision.
    #[must_use]
    pub fn mxid(&self) -> &str {
        &self.mxid
    }

    /// Ask to set the displayname of the user.
    ///
    /// # Parameters
    ///
    /// * `displayname` - The displayname to set.
    #[must_use]
    pub fn set_displayname(mut self, displayname: String) -> Self {
        self.displayname = FieldAction::Set(displayname);
        self
    }

    /// Ask to unset the displayname of the user.
    #[must_use]
    pub fn unset_displayname(mut self) -> Self {
        self.displayname = FieldAction::Unset;
        self
    }

    /// Call the given callback if the displayname should be set or unset.
    ///
    /// # Parameters
    ///
    /// * `callback` - The callback to call.
    pub fn on_displayname<F>(&self, callback: F) -> &Self
    where
        F: FnOnce(Option<&str>),
    {
        match &self.displayname {
            FieldAction::Unset => callback(None),
            FieldAction::Set(displayname) => callback(Some(displayname)),
            FieldAction::DoNothing => {}
        }

        self
    }

    /// Ask to set the avatar URL of the user.
    ///
    /// # Parameters
    ///
    /// * `avatar_url` - The avatar URL to set.
    #[must_use]
    pub fn set_avatar_url(mut self, avatar_url: String) -> Self {
        self.avatar_url = FieldAction::Set(avatar_url);
        self
    }

    /// Ask to unset the avatar URL of the user.
    #[must_use]
    pub fn unset_avatar_url(mut self) -> Self {
        self.avatar_url = FieldAction::Unset;
        self
    }

    /// Call the given callback if the avatar URL should be set or unset.
    ///
    /// # Parameters
    ///
    /// * `callback` - The callback to call.
    pub fn on_avatar_url<F>(&self, callback: F) -> &Self
    where
        F: FnOnce(Option<&str>),
    {
        match &self.avatar_url {
            FieldAction::Unset => callback(None),
            FieldAction::Set(avatar_url) => callback(Some(avatar_url)),
            FieldAction::DoNothing => {}
        }

        self
    }

    /// Ask to set the emails of the user.
    ///
    /// # Parameters
    ///
    /// * `emails` - The list of emails to set.
    #[must_use]
    pub fn set_emails(mut self, emails: Vec<String>) -> Self {
        self.emails = FieldAction::Set(emails);
        self
    }

    /// Ask to unset the emails of the user.
    #[must_use]
    pub fn unset_emails(mut self) -> Self {
        self.emails = FieldAction::Unset;
        self
    }

    /// Call the given callback if the emails should be set or unset.
    ///
    /// # Parameters
    ///
    /// * `callback` - The callback to call.
    pub fn on_emails<F>(&self, callback: F) -> &Self
    where
        F: FnOnce(Option<&[String]>),
    {
        match &self.emails {
            FieldAction::Unset => callback(None),
            FieldAction::Set(emails) => callback(Some(emails)),
            FieldAction::DoNothing => {}
        }

        self
    }
}

#[async_trait::async_trait]
pub trait HomeserverConnection: Send + Sync {
    /// The error type returned by all methods.
    type Error;

    /// Get the homeserver URL.
    fn homeserver(&self) -> &str;

    /// Get the Matrix ID of the user with the given localpart.
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart of the user.
    fn mxid(&self, localpart: &str) -> String {
        format!("@{}:{}", localpart, self.homeserver())
    }

    /// Query the state of a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `mxid` - The Matrix ID of the user to query.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the user does not
    /// exist.
    async fn query_user(&self, mxid: &str) -> Result<MatrixUser, Self::Error>;

    /// Provision a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `request` - a [`ProvisionRequest`] containing the details of the user
    ///   to provision.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the user could not
    /// be provisioned.
    async fn provision_user(&self, request: &ProvisionRequest) -> Result<bool, Self::Error>;

    /// Check whether a given username is available on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `localpart` - The localpart to check.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable.
    async fn is_localpart_available(&self, localpart: &str) -> Result<bool, Self::Error>;

    /// Create a device for a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `mxid` - The Matrix ID of the user to create a device for.
    /// * `device_id` - The device ID to create.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the device could
    /// not be created.
    async fn create_device(&self, mxid: &str, device_id: &str) -> Result<(), Self::Error>;

    /// Delete a device for a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `mxid` - The Matrix ID of the user to delete a device for.
    /// * `device_id` - The device ID to delete.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the device could
    /// not be deleted.
    async fn delete_device(&self, mxid: &str, device_id: &str) -> Result<(), Self::Error>;

    /// Delete a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `mxid` - The Matrix ID of the user to delete.
    /// * `erase` - Whether to ask the homeserver to erase the user's data.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the user could not
    /// be deleted.
    async fn delete_user(&self, mxid: &str, erase: bool) -> Result<(), Self::Error>;

    /// Set the displayname of a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `mxid` - The Matrix ID of the user to set the displayname for.
    /// * `displayname` - The displayname to set.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the displayname
    /// could not be set.
    async fn set_displayname(&self, mxid: &str, displayname: &str) -> Result<(), Self::Error>;

    /// Unset the displayname of a user on the homeserver.
    ///
    /// # Parameters
    ///
    /// * `mxid` - The Matrix ID of the user to unset the displayname for.
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the displayname
    /// could not be unset.
    async fn unset_displayname(&self, mxid: &str) -> Result<(), Self::Error>;

    /// Temporarily allow a user to reset their cross-signing keys.
    ///
    /// # Parameters
    ///
    /// * `mxid` - The Matrix ID of the user to allow cross-signing key reset
    ///
    /// # Errors
    ///
    /// Returns an error if the homeserver is unreachable or the cross-signing
    /// reset could not be allowed.
    async fn allow_cross_signing_reset(&self, mxid: &str) -> Result<(), Self::Error>;
}

#[async_trait::async_trait]
impl<T: HomeserverConnection + Send + Sync + ?Sized> HomeserverConnection for &T {
    type Error = T::Error;

    fn homeserver(&self) -> &str {
        (**self).homeserver()
    }

    async fn query_user(&self, mxid: &str) -> Result<MatrixUser, Self::Error> {
        (**self).query_user(mxid).await
    }

    async fn provision_user(&self, request: &ProvisionRequest) -> Result<bool, Self::Error> {
        (**self).provision_user(request).await
    }

    async fn is_localpart_available(&self, localpart: &str) -> Result<bool, Self::Error> {
        (**self).is_localpart_available(localpart).await
    }

    async fn create_device(&self, mxid: &str, device_id: &str) -> Result<(), Self::Error> {
        (**self).create_device(mxid, device_id).await
    }

    async fn delete_device(&self, mxid: &str, device_id: &str) -> Result<(), Self::Error> {
        (**self).delete_device(mxid, device_id).await
    }

    async fn delete_user(&self, mxid: &str, erase: bool) -> Result<(), Self::Error> {
        (**self).delete_user(mxid, erase).await
    }

    async fn set_displayname(&self, mxid: &str, displayname: &str) -> Result<(), Self::Error> {
        (**self).set_displayname(mxid, displayname).await
    }

    async fn unset_displayname(&self, mxid: &str) -> Result<(), Self::Error> {
        (**self).unset_displayname(mxid).await
    }

    async fn allow_cross_signing_reset(&self, mxid: &str) -> Result<(), Self::Error> {
        (**self).allow_cross_signing_reset(mxid).await
    }
}
