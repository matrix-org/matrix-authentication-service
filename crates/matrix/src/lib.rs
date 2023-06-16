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

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::str_to_string, rustdoc::broken_intra_doc_links)]
#![warn(clippy::pedantic)]

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
    #[must_use]
    pub fn new(mxid: String, sub: String) -> Self {
        Self {
            mxid,
            sub,
            displayname: FieldAction::DoNothing,
            avatar_url: FieldAction::DoNothing,
            emails: FieldAction::DoNothing,
        }
    }

    #[must_use]
    pub fn sub(&self) -> &str {
        &self.sub
    }

    #[must_use]
    pub fn mxid(&self) -> &str {
        &self.mxid
    }

    #[must_use]
    pub fn set_displayname(mut self, displayname: String) -> Self {
        self.displayname = FieldAction::Set(displayname);
        self
    }

    #[must_use]
    pub fn unset_displayname(mut self) -> Self {
        self.displayname = FieldAction::Unset;
        self
    }

    pub fn on_displayname(&self, callback: impl FnOnce(Option<&str>)) -> &Self {
        match &self.displayname {
            FieldAction::DoNothing => callback(None),
            FieldAction::Set(displayname) => callback(Some(displayname)),
            FieldAction::Unset => {}
        }

        self
    }

    #[must_use]
    pub fn set_avatar_url(mut self, avatar_url: String) -> Self {
        self.avatar_url = FieldAction::Set(avatar_url);
        self
    }

    #[must_use]
    pub fn unset_avatar_url(mut self) -> Self {
        self.avatar_url = FieldAction::Unset;
        self
    }

    pub fn on_avatar_url(&self, callback: impl FnOnce(Option<&str>)) -> &Self {
        match &self.avatar_url {
            FieldAction::DoNothing => callback(None),
            FieldAction::Set(avatar_url) => callback(Some(avatar_url)),
            FieldAction::Unset => {}
        }

        self
    }

    #[must_use]
    pub fn set_emails(mut self, emails: Vec<String>) -> Self {
        self.emails = FieldAction::Set(emails);
        self
    }

    #[must_use]
    pub fn unset_emails(mut self) -> Self {
        self.emails = FieldAction::Unset;
        self
    }

    pub fn on_emails(&self, callback: impl FnOnce(Option<&[String]>)) -> &Self {
        match &self.emails {
            FieldAction::DoNothing => callback(None),
            FieldAction::Set(emails) => callback(Some(emails)),
            FieldAction::Unset => {}
        }

        self
    }
}

#[async_trait::async_trait]
pub trait HomeserverConnection: Send + Sync {
    type Error;

    fn homeserver(&self) -> &str;
    fn mxid(&self, localpart: &str) -> String {
        format!("@{}:{}", localpart, self.homeserver())
    }

    async fn query_user(&self, mxid: &str) -> Result<MatrixUser, Self::Error>;
    async fn provision_user(&self, request: &ProvisionRequest) -> Result<bool, Self::Error>;
    async fn create_device(&self, mxid: &str, device_id: &str) -> Result<(), Self::Error>;
    async fn delete_device(&self, mxid: &str, device_id: &str) -> Result<(), Self::Error>;
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

    async fn create_device(&self, mxid: &str, device_id: &str) -> Result<(), Self::Error> {
        (**self).create_device(mxid, device_id).await
    }

    async fn delete_device(&self, mxid: &str, device_id: &str) -> Result<(), Self::Error> {
        (**self).delete_device(mxid, device_id).await
    }
}
