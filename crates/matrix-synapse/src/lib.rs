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

use http::{header::AUTHORIZATION, request::Builder, Method, Request, StatusCode};
use mas_axum_utils::http_client_factory::HttpClientFactory;
use mas_http::{EmptyBody, HttpServiceExt};
use mas_matrix::{HomeserverConnection, MatrixUser, ProvisionRequest};
use serde::{Deserialize, Serialize};
use tower::{Service, ServiceExt};
use url::Url;

static SYNAPSE_AUTH_PROVIDER: &str = "oauth-delegated";

pub struct SynapseConnection {
    homeserver: String,
    endpoint: Url,
    access_token: String,
    http_client_factory: HttpClientFactory,
}

impl SynapseConnection {
    #[must_use]
    pub fn new(
        homeserver: String,
        endpoint: Url,
        access_token: String,
        http_client_factory: HttpClientFactory,
    ) -> Self {
        Self {
            homeserver,
            endpoint,
            access_token,
            http_client_factory,
        }
    }

    fn builder(&self, url: &str) -> Builder {
        Request::builder()
            .uri(
                self.endpoint
                    .join(url)
                    .map(String::from)
                    .unwrap_or_default(),
            )
            .header(AUTHORIZATION, format!("Bearer {}", self.access_token))
    }

    #[must_use]
    pub fn post(&self, url: &str) -> Builder {
        self.builder(url).method(Method::POST)
    }

    #[must_use]
    pub fn get(&self, url: &str) -> Builder {
        self.builder(url).method(Method::GET)
    }

    #[must_use]
    pub fn put(&self, url: &str) -> Builder {
        self.builder(url).method(Method::PUT)
    }

    #[must_use]
    pub fn delete(&self, url: &str) -> Builder {
        self.builder(url).method(Method::DELETE)
    }
}

#[derive(Serialize, Deserialize)]
struct ExternalID {
    auth_provider: String,
    external_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ThreePIDMedium {
    Email,
    Msisdn,
}

#[derive(Serialize, Deserialize)]
struct ThreePID {
    medium: ThreePIDMedium,
    address: String,
}

#[derive(Default, Serialize, Deserialize)]
struct SynapseUser {
    #[serde(
        default,
        rename = "displayname",
        skip_serializing_if = "Option::is_none"
    )]
    display_name: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    avatar_url: Option<String>,

    #[serde(default, rename = "threepids", skip_serializing_if = "Option::is_none")]
    three_pids: Option<Vec<ThreePID>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    external_ids: Option<Vec<ExternalID>>,
}

#[derive(Serialize)]
struct SynapseDevice<'a> {
    device_id: &'a str,
}

#[derive(Serialize)]
struct SetDisplayNameRequest<'a> {
    displayname: &'a str,
}

#[derive(Serialize)]
struct SynapseDeactivateUserRequest {
    erase: bool,
}

#[derive(Serialize)]
struct SynapseAllowCrossSigningResetRequest {}

#[async_trait::async_trait]
impl HomeserverConnection for SynapseConnection {
    type Error = anyhow::Error;

    fn homeserver(&self) -> &str {
        &self.homeserver
    }

    #[tracing::instrument(
        name = "homeserver.query_user",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
        ),
        err(Display),
    )]
    async fn query_user(&self, mxid: &str) -> Result<MatrixUser, Self::Error> {
        let mut client = self
            .http_client_factory
            .client("homeserver.query_user")
            .response_body_to_bytes()
            .json_response();

        let request = self
            .get(&format!("_synapse/admin/v2/users/{mxid}"))
            .body(EmptyBody::new())?;

        let response = client.ready().await?.call(request).await?;

        if response.status() != StatusCode::OK {
            return Err(anyhow::anyhow!("Failed to query user from Synapse"));
        }

        let body: SynapseUser = response.into_body();

        Ok(MatrixUser {
            displayname: body.display_name,
            avatar_url: body.avatar_url,
        })
    }

    #[tracing::instrument(
        name = "homeserver.is_localpart_available",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
        ),
        err(Display),
    )]
    async fn is_localpart_available(&self, localpart: &str) -> Result<bool, Self::Error> {
        let mut client = self
            .http_client_factory
            .client("homeserver.is_localpart_available");

        let request = self
            .get(&format!(
                "_synapse/admin/v1/username_available?username={localpart}"
            ))
            .body(EmptyBody::new())?;

        let response = client.ready().await?.call(request).await?;

        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::BAD_REQUEST => Ok(false),
            _ => Err(anyhow::anyhow!(
                "Failed to query localpart availability from Synapse"
            )),
        }
    }

    #[tracing::instrument(
        name = "homeserver.provision_user",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = request.mxid(),
            user.id = request.sub(),
        ),
        err(Display),
    )]
    async fn provision_user(&self, request: &ProvisionRequest) -> Result<bool, Self::Error> {
        let mut body = SynapseUser {
            external_ids: Some(vec![ExternalID {
                auth_provider: SYNAPSE_AUTH_PROVIDER.to_owned(),
                external_id: request.sub().to_owned(),
            }]),
            ..SynapseUser::default()
        };

        request
            .on_displayname(|displayname| {
                body.display_name = Some(displayname.unwrap_or_default().to_owned());
            })
            .on_avatar_url(|avatar_url| {
                body.avatar_url = Some(avatar_url.unwrap_or_default().to_owned());
            })
            .on_emails(|emails| {
                body.three_pids = Some(
                    emails
                        .unwrap_or_default()
                        .iter()
                        .map(|email| ThreePID {
                            medium: ThreePIDMedium::Email,
                            address: email.clone(),
                        })
                        .collect(),
                );
            });

        let mut client = self
            .http_client_factory
            .client("homeserver.provision_user")
            .request_bytes_to_body()
            .json_request();

        let request = self
            .put(&format!(
                "_synapse/admin/v2/users/{mxid}",
                mxid = request.mxid()
            ))
            .body(body)?;

        let response = client.ready().await?.call(request).await?;

        match response.status() {
            StatusCode::CREATED => Ok(true),
            StatusCode::OK => Ok(false),
            code => Err(anyhow::anyhow!(
                "Failed to provision user in Synapse: {}",
                code
            )),
        }
    }

    #[tracing::instrument(
        name = "homeserver.create_device",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
            matrix.device_id = device_id,
        ),
        err(Display),
    )]
    async fn create_device(&self, mxid: &str, device_id: &str) -> Result<(), Self::Error> {
        let mut client = self
            .http_client_factory
            .client("homeserver.create_device")
            .request_bytes_to_body()
            .json_request();

        let request = self
            .post(&format!("_synapse/admin/v2/users/{mxid}/devices"))
            .body(SynapseDevice { device_id })?;

        let response = client.ready().await?.call(request).await?;

        if response.status() != StatusCode::CREATED {
            return Err(anyhow::anyhow!("Failed to create device in Synapse"));
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.delete_device",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
            matrix.device_id = device_id,
        ),
        err(Display),
    )]
    async fn delete_device(&self, mxid: &str, device_id: &str) -> Result<(), Self::Error> {
        let mut client = self.http_client_factory.client("homeserver.delete_device");

        let request = self
            .delete(&format!(
                "_synapse/admin/v2/users/{mxid}/devices/{device_id}"
            ))
            .body(EmptyBody::new())?;

        let response = client.ready().await?.call(request).await?;

        if response.status() != StatusCode::OK {
            return Err(anyhow::anyhow!("Failed to delete device in Synapse"));
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.delete_user",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
            erase = erase,
        ),
        err(Display),
    )]
    async fn delete_user(&self, mxid: &str, erase: bool) -> Result<(), Self::Error> {
        let mut client = self
            .http_client_factory
            .client("homeserver.delete_user")
            .request_bytes_to_body()
            .json_request();

        let request = self
            .post(&format!("_synapse/admin/v1/deactivate/{mxid}"))
            .body(SynapseDeactivateUserRequest { erase })?;

        let response = client.ready().await?.call(request).await?;

        if response.status() != StatusCode::OK {
            return Err(anyhow::anyhow!("Failed to delete user in Synapse"));
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.set_displayname",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
            matrix.displayname = displayname,
        ),
        err(Display),
    )]
    async fn set_displayname(&self, mxid: &str, displayname: &str) -> Result<(), Self::Error> {
        let mut client = self
            .http_client_factory
            .client("homeserver.set_displayname")
            .request_bytes_to_body()
            .json_request();

        let request = self
            .put(&format!("_matrix/client/v3/profile/{mxid}/displayname"))
            .body(SetDisplayNameRequest { displayname })?;

        let response = client.ready().await?.call(request).await?;

        if response.status() != StatusCode::OK {
            return Err(anyhow::anyhow!("Failed to set displayname in Synapse"));
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.unset_displayname",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
        ),
        err(Display),
    )]
    async fn unset_displayname(&self, mxid: &str) -> Result<(), Self::Error> {
        self.set_displayname(mxid, "").await
    }

    #[tracing::instrument(
        name = "homeserver.allow_cross_signing_reset",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
        ),
        err(Display),
    )]
    async fn allow_cross_signing_reset(&self, mxid: &str) -> Result<(), Self::Error> {
        let mut client = self
            .http_client_factory
            .client("homeserver.allow_cross_signing_reset")
            .request_bytes_to_body()
            .json_request();

        let request = self
            .post(&format!(
                "_synapse/admin/v1/users/{mxid}/_allow_cross_signing_replacement_without_uia"
            ))
            .body(SynapseAllowCrossSigningResetRequest {})?;

        let response = client.ready().await?.call(request).await?;

        if response.status() != StatusCode::OK {
            return Err(anyhow::anyhow!(
                "Failed to allow cross signing reset in Synapse"
            ));
        }

        Ok(())
    }
}
