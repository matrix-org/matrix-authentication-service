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

use async_trait::async_trait;
use aws_sdk_sesv2::{
    model::{EmailContent, RawMessage},
    Blob, Client,
};
use lettre::{address::Envelope, AsyncTransport};

pub struct Transport {
    client: Client,
}

impl Transport {
    pub async fn from_env() -> Self {
        let config = aws_config::from_env().load().await;
        Self::new(&config)
    }

    pub fn new(config: &aws_config::Config) -> Self {
        let client = Client::new(config);
        Self { client }
    }
}

#[async_trait]
impl AsyncTransport for Transport {
    type Ok = ();
    type Error = anyhow::Error;

    async fn send_raw(&self, _envelope: &Envelope, email: &[u8]) -> Result<Self::Ok, Self::Error> {
        let email = Blob::new(email);
        let email = RawMessage::builder().data(email).build();
        let email = EmailContent::builder().raw(email).build();

        let req = self.client.send_email().content(email);
        req.send().await?;

        Ok(())
    }
}
