// Copyright 2022 The Matrix.org Foundation C.I.C.
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

//! Helps sending emails to users, with different email backends

#![deny(missing_docs)]

mod mailer;
mod transport;

pub use lettre::{
    address::{Address, AddressError},
    message::Mailbox,
    transport::smtp::authentication::Credentials as SmtpCredentials,
};
pub use mas_templates::EmailVerificationContext;

pub use self::{
    mailer::{Error as MailerError, Mailer},
    transport::{SmtpMode, Transport as MailTransport},
};
