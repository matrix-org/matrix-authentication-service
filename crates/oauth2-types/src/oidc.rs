// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use std::ops::Deref;

use language_tags::LanguageTag;
use mas_iana::{
    jose::{JsonWebEncryptionAlg, JsonWebEncryptionEnc, JsonWebSignatureAlg},
    oauth::{
        OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod,
        PkceCodeChallengeMethod,
    },
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use thiserror::Error;
use url::Url;

use crate::requests::{Display, GrantType, Prompt, ResponseMode};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationType {
    Web,
    Native,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    Public,
    Pairwise,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ClaimType {
    Normal,
    Aggregated,
    Distributed,
}

pub static DEFAULT_RESPONSE_MODES_SUPPORTED: &[ResponseMode] =
    &[ResponseMode::Query, ResponseMode::Fragment];

pub static DEFAULT_GRANT_TYPES_SUPPORTED: &[GrantType] =
    &[GrantType::AuthorizationCode, GrantType::Implicit];

pub static DEFAULT_AUTH_METHODS_SUPPORTED: &[OAuthClientAuthenticationMethod] =
    &[OAuthClientAuthenticationMethod::ClientSecretBasic];

pub static DEFAULT_CLAIM_TYPES_SUPPORTED: &[ClaimType] = &[ClaimType::Normal];

/// Authorization server metadata, as described by the [IANA registry].
///
/// All the fields with a default value are accessible via methods.
///
/// [IANA registry]: https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#authorization-server-metadata
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProviderMetadata {
    /// Authorization server's issuer identifier URL.
    ///
    /// This field is required. The URL must use a `https` scheme, and must not
    /// contain a query or fragment. It must match the one used to build the
    /// well-known URI to query this metadata.
    pub issuer: Option<Url>,

    /// URL of the authorization server's [authorization endpoint].
    ///
    /// This field is required. The URL must use a `https` scheme, and must not
    /// contain a fragment.
    ///
    /// [authorization endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
    pub authorization_endpoint: Option<Url>,

    /// URL of the authorization server's [token endpoint].
    ///
    /// This field is required. The URL must use a `https` scheme, and must not
    /// contain a fragment.
    ///
    /// [token endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
    pub token_endpoint: Option<Url>,

    /// URL of the authorization server's [JWK] Set document.
    ///
    /// This field is required. The URL must use a `https` scheme.
    ///
    /// [JWK]: https://www.rfc-editor.org/rfc/rfc7517.html
    pub jwks_uri: Option<Url>,

    /// URL of the authorization server's [OAuth 2.0 Dynamic Client
    /// Registration] endpoint.
    ///
    /// If this field is present, the URL must use a `https` scheme.
    ///
    /// [OAuth 2.0 Dynamic Client Registration]: https://www.rfc-editor.org/rfc/rfc7591
    pub registration_endpoint: Option<Url>,

    /// JSON array containing a list of the OAuth 2.0 `scope` values that this
    /// authorization server supports.
    ///
    /// If this field is present, it must contain at least the `openid` scope
    /// value.
    pub scopes_supported: Option<Vec<String>>,

    /// JSON array containing a list of the [OAuth 2.0 `response_type` values]
    /// that this authorization server supports.
    ///
    /// This field is required.
    ///
    /// [OAuth 2.0 `response_type` values]: https://www.rfc-editor.org/rfc/rfc7591#page-9
    pub response_types_supported: Option<Vec<OAuthAuthorizationEndpointResponseType>>,

    /// JSON array containing a list of the [OAuth 2.0 `response_mode` values]
    /// that this authorization server supports.
    ///
    /// Defaults to [`DEFAULT_RESPONSE_MODES_SUPPORTED`].
    ///
    /// [OAuth 2.0 `response_mode` values]: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
    pub response_modes_supported: Option<Vec<ResponseMode>>,

    /// JSON array containing a list of the [OAuth 2.0 `grant_type` values] that
    /// this authorization server supports.
    ///
    /// Defaults to [`DEFAULT_GRANT_TYPES_SUPPORTED`].
    ///
    /// [OAuth 2.0 `grant_type` values]: https://www.rfc-editor.org/rfc/rfc7591#page-9
    pub grant_types_supported: Option<Vec<GrantType>>,

    /// JSON array containing a list of client authentication methods supported
    /// by this token endpoint.
    ///
    /// Defaults to [`DEFAULT_AUTH_METHODS_SUPPORTED`].
    pub token_endpoint_auth_methods_supported: Option<Vec<OAuthClientAuthenticationMethod>>,

    /// JSON array containing a list of the JWS signing algorithms supported
    /// by the token endpoint for the signature on the JWT used to
    /// authenticate the client at the token endpoint.
    ///
    /// If this field is present, it must not contain
    /// [`JsonWebSignatureAlg::None`]. This field is required if
    /// `token_endpoint_auth_methods_supported` contains
    /// [`OAuthClientAuthenticationMethod::PrivateKeyJwt`] or
    /// [`OAuthClientAuthenticationMethod::ClientSecretJwt`].
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<JsonWebSignatureAlg>>,

    /// URL of a page containing human-readable information that developers
    /// might want or need to know when using the authorization server.
    pub service_documentation: Option<Url>,

    /// Languages and scripts supported for the user interface, represented as a
    /// JSON array of language tag values from BCP 47.
    ///
    /// If omitted, the set of supported languages and scripts is unspecified.
    pub ui_locales_supported: Option<Vec<LanguageTag>>,

    /// URL that the authorization server provides to the person registering the
    /// client to read about the authorization server's requirements on how the
    /// client can use the data provided by the authorization server.
    pub op_policy_uri: Option<Url>,

    /// URL that the authorization server provides to the person registering the
    /// client to read about the authorization server's terms of service.
    pub op_tos_uri: Option<Url>,

    /// URL of the authorization server's [OAuth 2.0 revocation endpoint].
    ///
    /// If this field is present, the URL must use a `https` scheme, and must
    /// not contain a fragment.
    ///
    /// [OAuth 2.0 revocation endpoint]: https://www.rfc-editor.org/rfc/rfc7009
    pub revocation_endpoint: Option<Url>,

    /// JSON array containing a list of client authentication methods supported
    /// by this revocation endpoint.
    ///
    /// Defaults to [`DEFAULT_AUTH_METHODS_SUPPORTED`].
    pub revocation_endpoint_auth_methods_supported: Option<Vec<OAuthClientAuthenticationMethod>>,

    /// JSON array containing a list of the JWS signing algorithms supported by
    /// the revocation endpoint for the signature on the JWT used to
    /// authenticate the client at the revocation endpoint.
    ///
    /// If this field is present, it must not contain
    /// [`JsonWebSignatureAlg::None`]. This field is required if
    /// `revocation_endpoint_auth_methods_supported` contains
    /// [`OAuthClientAuthenticationMethod::PrivateKeyJwt`] or
    /// [`OAuthClientAuthenticationMethod::ClientSecretJwt`].
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<JsonWebSignatureAlg>>,

    /// URL of the authorization server's [OAuth 2.0 introspection endpoint].
    ///
    /// If this field is present, the URL must use a `https` scheme.
    ///
    /// [OAuth 2.0 introspection endpoint]: https://www.rfc-editor.org/rfc/rfc7662
    pub introspection_endpoint: Option<Url>,

    /// JSON array containing a list of client authentication methods supported
    /// by this introspection endpoint.
    pub introspection_endpoint_auth_methods_supported: Option<Vec<OAuthClientAuthenticationMethod>>,

    /// JSON array containing a list of the JWS signing algorithms supported by
    /// the introspection endpoint for the signature on the JWT used to
    /// authenticate the client at the introspection endpoint.
    ///
    /// If this field is present, it must not contain
    /// [`JsonWebSignatureAlg::None`]. This field is required if
    /// `intospection_endpoint_auth_methods_supported` contains
    /// [`OAuthClientAuthenticationMethod::PrivateKeyJwt`] or
    /// [`OAuthClientAuthenticationMethod::ClientSecretJwt`].
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<JsonWebSignatureAlg>>,

    /// [PKCE code challenge methods] supported by this authorization server.
    /// If omitted, the authorization server does not support PKCE.
    ///
    /// [PKCE code challenge]: https://www.rfc-editor.org/rfc/rfc7636
    pub code_challenge_methods_supported: Option<Vec<PkceCodeChallengeMethod>>,

    /// URL of the OP's [UserInfo Endpoint].
    ///
    /// [UserInfo Endpoint]: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
    pub userinfo_endpoint: Option<Url>,

    /// JSON array containing a list of the Authentication Context Class
    /// References that this OP supports.
    pub acr_values_supported: Option<Vec<String>>,

    /// JSON array containing a list of the Subject Identifier types that this
    /// OP supports.
    ///
    /// This field is required.
    pub subject_types_supported: Option<Vec<SubjectType>>,

    /// JSON array containing a list of the JWS signing algorithms (`alg`
    /// values) supported by the OP for the ID Token.
    ///
    /// This field is required and must contain [`JsonWebSignatureAlg::Rs256`].
    pub id_token_signing_alg_values_supported: Option<Vec<JsonWebSignatureAlg>>,

    /// JSON array containing a list of the JWE encryption algorithms (`alg`
    /// values) supported by the OP for the ID Token.
    pub id_token_encryption_alg_values_supported: Option<Vec<JsonWebEncryptionAlg>>,

    /// JSON array containing a list of the JWE encryption algorithms (`enc`
    /// values) supported by the OP for the ID Token.
    pub id_token_encryption_enc_values_supported: Option<Vec<JsonWebEncryptionEnc>>,

    /// JSON array containing a list of the JWS signing algorithms (`alg`
    /// values) supported by the UserInfo Endpoint.
    pub userinfo_signing_alg_values_supported: Option<Vec<JsonWebSignatureAlg>>,

    /// JSON array containing a list of the JWE encryption algorithms (`alg`
    /// values) supported by the UserInfo Endpoint.
    pub userinfo_encryption_alg_values_supported: Option<Vec<JsonWebEncryptionAlg>>,

    /// JSON array containing a list of the JWE encryption algorithms (`enc`
    /// values) supported by the UserInfo Endpoint.
    pub userinfo_encryption_enc_values_supported: Option<Vec<JsonWebEncryptionEnc>>,

    /// JSON array containing a list of the JWS signing algorithms (`alg`
    /// values) supported by the OP for Request Objects.
    pub request_object_signing_alg_values_supported: Option<Vec<JsonWebSignatureAlg>>,

    /// JSON array containing a list of the JWE encryption algorithms (`alg`
    /// values) supported by the OP for Request Objects.
    pub request_object_encryption_alg_values_supported: Option<Vec<JsonWebEncryptionAlg>>,

    /// JSON array containing a list of the JWE encryption algorithms (`enc`
    /// values) supported by the OP for Request Objects.
    pub request_object_encryption_enc_values_supported: Option<Vec<JsonWebEncryptionEnc>>,

    /// JSON array containing a list of the "display" parameter values that the
    /// OpenID Provider supports.
    pub display_values_supported: Option<Vec<Display>>,

    /// JSON array containing a list of the Claim Types that the OpenID Provider
    /// supports.
    ///
    /// Defaults to [`DEFAULT_CLAIM_TYPES_SUPPORTED`].
    pub claim_types_supported: Option<Vec<ClaimType>>,

    /// JSON array containing a list of the Claim Names of the Claims that the
    /// OpenID Provider MAY be able to supply values for.
    pub claims_supported: Option<Vec<String>>,

    /// Languages and scripts supported for values in Claims being returned,
    /// represented as a JSON array of BCP 47 language tag values.
    pub claims_locales_supported: Option<Vec<LanguageTag>>,

    /// Boolean value specifying whether the OP supports use of the `claims`
    /// parameter.
    ///
    /// Defaults to `false`.
    pub claims_parameter_supported: Option<bool>,

    /// Boolean value specifying whether the OP supports use of the `request`
    /// parameter.
    ///
    /// Defaults to `false`.
    pub request_parameter_supported: Option<bool>,

    /// Boolean value specifying whether the OP supports use of the
    /// `request_uri` parameter.
    ///
    /// Defaults to `true`.
    pub request_uri_parameter_supported: Option<bool>,

    /// Boolean value specifying whether the OP requires any `request_uri`
    /// values used to be pre-registered.
    ///
    /// Defaults to `false`.
    pub require_request_uri_registration: Option<bool>,

    /// Indicates where authorization request needs to be protected as [Request
    /// Object] and provided through either request or request_uri parameter.
    ///
    /// Defaults to `false`.
    ///
    /// [Request Object]: https://www.rfc-editor.org/rfc/rfc9101.html
    pub require_signed_request_object: Option<bool>,

    /// URL of the authorization server's [pushed authorization request
    /// endpoint].
    ///
    /// [pushed authorization request endpoint]: https://www.rfc-editor.org/rfc/rfc9126.html
    pub pushed_authorization_request_endpoint: Option<Url>,

    /// Indicates whether the authorization server accepts authorization
    /// requests only via PAR.
    ///
    /// Defaults to `false`.
    pub require_pushed_authorization_requests: Option<bool>,

    /// Array containing the list of prompt values that this OP supports.
    ///
    /// This field can be used to detect if the OP supports the [prompt
    /// `create`] value.
    ///
    /// [prompt `create`]: https://openid.net/specs/openid-connect-prompt-create-1_0.html
    pub prompt_values_supported: Option<Vec<Prompt>>,
}

impl ProviderMetadata {
    /// Validate this `ProviderMetadata` according to the [OpenID Connect
    /// Discovery Spec 1.0].
    ///
    /// # Parameters
    ///
    /// - `issuer`: The issuer that was discovered to get this
    ///   `ProviderMetadata`.
    ///
    /// # Errors
    ///
    /// Will return `Err` if validation fails.
    ///
    /// [OpenID Connect Discovery Spec 1.0]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    pub fn validate(
        self,
        issuer: &Url,
    ) -> Result<VerifiedProviderMetadata, ProviderMetadataVerificationError> {
        let metadata = self.insecure_verify_metadata()?;

        if metadata.issuer() != issuer {
            return Err(ProviderMetadataVerificationError::IssuerUrlsDontMatch);
        }

        validate_url(
            "issuer",
            metadata.issuer(),
            ExtraUrlRestrictions::NoQueryOrFragment,
        )?;

        validate_url(
            "authorization_endpoint",
            metadata.authorization_endpoint(),
            ExtraUrlRestrictions::NoFragment,
        )?;

        validate_url(
            "token_endpoint",
            metadata.token_endpoint(),
            ExtraUrlRestrictions::NoFragment,
        )?;

        validate_url("jwks_uri", metadata.jwks_uri(), ExtraUrlRestrictions::None)?;

        if let Some(url) = &metadata.registration_endpoint {
            validate_url("registration_endpoint", url, ExtraUrlRestrictions::None)?;
        }

        if let Some(scopes) = &metadata.scopes_supported {
            if !scopes.iter().any(|s| s == "openid") {
                return Err(ProviderMetadataVerificationError::ScopesMissingOpenid);
            }
        }

        validate_signing_alg_values_supported(
            "token_endpoint",
            &metadata.token_endpoint_auth_signing_alg_values_supported,
            &metadata.token_endpoint_auth_methods_supported,
        )?;

        if let Some(url) = &metadata.revocation_endpoint {
            validate_url("revocation_endpoint", url, ExtraUrlRestrictions::NoFragment)?;
        }

        validate_signing_alg_values_supported(
            "revocation_endpoint",
            &metadata.revocation_endpoint_auth_signing_alg_values_supported,
            &metadata.revocation_endpoint_auth_methods_supported,
        )?;

        if let Some(url) = &metadata.introspection_endpoint {
            validate_url("introspection_endpoint", url, ExtraUrlRestrictions::None)?;
        }

        validate_signing_alg_values_supported(
            "introspection_endpoint",
            &metadata.introspection_endpoint_auth_signing_alg_values_supported,
            &metadata.introspection_endpoint_auth_methods_supported,
        )?;

        if let Some(url) = &metadata.userinfo_endpoint {
            validate_url("userinfo_endpoint", url, ExtraUrlRestrictions::None)?;
        }

        if !metadata
            .id_token_signing_alg_values_supported()
            .contains(&JsonWebSignatureAlg::Rs256)
        {
            return Err(
                ProviderMetadataVerificationError::SigningAlgValuesMissingRs256("id_token"),
            );
        }

        if let Some(url) = &metadata.pushed_authorization_request_endpoint {
            validate_url(
                "pushed_authorization_request_endpoint",
                url,
                ExtraUrlRestrictions::None,
            )?;
        }

        Ok(metadata)
    }

    /// Verify this `ProviderMetadata`.
    ///
    /// Contrary to [`ProviderMetadata::validate()`], it only checks that the
    /// required fields are present.
    ///
    /// This can be used during development to test against a local OpenID
    /// Provider, for example.
    ///
    /// # Parameters
    ///
    /// - `issuer`: The issuer that was discovered to get this
    ///   `ProviderMetadata`.
    ///
    /// # Errors
    ///
    /// Will return `Err` if a required field is missing.
    ///
    /// # Warning
    ///
    /// It is not recommended to use this method in production as it doesn't
    /// ensure that the issuer implements the proper security practices.
    pub fn insecure_verify_metadata(
        self,
    ) -> Result<VerifiedProviderMetadata, ProviderMetadataVerificationError> {
        self.issuer
            .as_ref()
            .ok_or(ProviderMetadataVerificationError::MissingIssuer)?;

        self.authorization_endpoint
            .as_ref()
            .ok_or(ProviderMetadataVerificationError::MissingAuthorizationEndpoint)?;

        self.token_endpoint
            .as_ref()
            .ok_or(ProviderMetadataVerificationError::MissingTokenEndpoint)?;

        self.jwks_uri
            .as_ref()
            .ok_or(ProviderMetadataVerificationError::MissingJwksUri)?;

        self.response_types_supported
            .as_ref()
            .ok_or(ProviderMetadataVerificationError::MissingResponseTypesSupported)?;

        self.subject_types_supported
            .as_ref()
            .ok_or(ProviderMetadataVerificationError::MissingSubjectTypesSupported)?;

        self.id_token_signing_alg_values_supported
            .as_ref()
            .ok_or(ProviderMetadataVerificationError::MissingIdTokenSigningAlgValuesSupported)?;

        Ok(VerifiedProviderMetadata { inner: self })
    }

    /// JSON array containing a list of the OAuth 2.0 `response_mode` values
    /// that this authorization server supports.
    ///
    /// Defaults to [`DEFAULT_RESPONSE_MODES_SUPPORTED`].
    #[must_use]
    pub fn response_modes_supported(&self) -> &[ResponseMode] {
        self.response_modes_supported
            .as_deref()
            .unwrap_or(DEFAULT_RESPONSE_MODES_SUPPORTED)
    }

    /// JSON array containing a list of the OAuth 2.0 grant type values that
    /// this authorization server supports.
    ///
    /// Defaults to [`DEFAULT_GRANT_TYPES_SUPPORTED`].
    #[must_use]
    pub fn grant_types_supported(&self) -> &[GrantType] {
        self.grant_types_supported
            .as_deref()
            .unwrap_or(DEFAULT_GRANT_TYPES_SUPPORTED)
    }

    /// JSON array containing a list of client authentication methods supported
    /// by the token endpoint.
    ///
    /// Defaults to [`DEFAULT_AUTH_METHODS_SUPPORTED`].
    #[must_use]
    pub fn token_endpoint_auth_methods_supported(&self) -> &[OAuthClientAuthenticationMethod] {
        self.token_endpoint_auth_methods_supported
            .as_deref()
            .unwrap_or(DEFAULT_AUTH_METHODS_SUPPORTED)
    }

    /// JSON array containing a list of client authentication methods supported
    /// by the revocation endpoint.
    ///
    /// Defaults to [`DEFAULT_AUTH_METHODS_SUPPORTED`].
    #[must_use]
    pub fn revocation_endpoint_auth_methods_supported(&self) -> &[OAuthClientAuthenticationMethod] {
        self.revocation_endpoint_auth_methods_supported
            .as_deref()
            .unwrap_or(DEFAULT_AUTH_METHODS_SUPPORTED)
    }

    /// JSON array containing a list of the Claim Types that the OpenID Provider
    /// supports.
    ///
    /// Defaults to [`DEFAULT_CLAIM_TYPES_SUPPORTED`].
    #[must_use]
    pub fn claim_types_supported(&self) -> &[ClaimType] {
        self.claim_types_supported
            .as_deref()
            .unwrap_or(DEFAULT_CLAIM_TYPES_SUPPORTED)
    }

    /// Boolean value specifying whether the OP supports use of the `claims`
    /// parameter.
    ///
    /// Defaults to `false`.
    #[must_use]
    pub fn claims_parameter_supported(&self) -> bool {
        self.claims_parameter_supported.unwrap_or(false)
    }

    /// Boolean value specifying whether the OP supports use of the `request`
    /// parameter.
    ///
    /// Defaults to `false`.
    #[must_use]
    pub fn request_parameter_supported(&self) -> bool {
        self.request_parameter_supported.unwrap_or(false)
    }

    /// Boolean value specifying whether the OP supports use of the
    /// `request_uri` parameter.
    ///
    /// Defaults to `true`.
    #[must_use]
    pub fn request_uri_parameter_supported(&self) -> bool {
        self.request_uri_parameter_supported.unwrap_or(true)
    }

    /// Boolean value specifying whether the OP requires any `request_uri`
    /// values used to be pre-registered.
    ///
    /// Defaults to `false`.
    #[must_use]
    pub fn require_request_uri_registration(&self) -> bool {
        self.require_request_uri_registration.unwrap_or(false)
    }

    /// Indicates where authorization request needs to be protected as Request
    /// Object and provided through either `request` or `request_uri` parameter.
    ///
    /// Defaults to `false`.
    #[must_use]
    pub fn require_signed_request_object(&self) -> bool {
        self.require_signed_request_object.unwrap_or(false)
    }

    /// Indicates whether the authorization server accepts authorization
    /// requests only via PAR.
    ///
    /// Defaults to `false`.
    #[must_use]
    pub fn require_pushed_authorization_requests(&self) -> bool {
        self.require_pushed_authorization_requests.unwrap_or(false)
    }
}

/// The verified authorization server metadata.
///
/// All the fields required by the [OpenID Connect Discovery Spec 1.0] or with
/// a default value are accessible via methods.
///
/// To access other fields, use this type's `Deref` implementation.
///
/// # Example
///
/// ```no_run
/// use oauth2_types::{
///     oidc::VerifiedProviderMetadata,
///     requests::GrantType,
/// };
/// use url::Url;
/// # use oauth2_types::oidc::{ProviderMetadata, ProviderMetadataVerificationError};
/// # let metadata = ProviderMetadata::default();
/// # let issuer = Url::parse("http://localhost").unwrap();
/// let verified_metadata = metadata.validate(&issuer)?;
///
/// // The endpoint is required during validation so this is not an `Option`.
/// let _: &Url = verified_metadata.authorization_endpoint();
///
/// // The field has a default value so this is not an `Option`.
/// let _: &[GrantType] = verified_metadata.grant_types_supported();
///
/// // Other fields can be accessed via `Deref`.
/// if let Some(registration_endpoint) = &verified_metadata.registration_endpoint {
///     println!("Registration is supported at {registration_endpoint}");
/// }
/// # Ok::<(), ProviderMetadataVerificationError>(())
/// ```
///
/// [OpenID Connect Discovery Spec 1.0]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
#[derive(Debug, Clone)]
pub struct VerifiedProviderMetadata {
    inner: ProviderMetadata,
}

impl VerifiedProviderMetadata {
    /// Authorization server's issuer identifier URL.
    #[must_use]
    pub fn issuer(&self) -> &Url {
        match &self.issuer {
            Some(u) => u,
            None => unreachable!(),
        }
    }

    /// URL of the authorization server's authorization endpoint.
    #[must_use]
    pub fn authorization_endpoint(&self) -> &Url {
        match &self.authorization_endpoint {
            Some(u) => u,
            None => unreachable!(),
        }
    }

    /// URL of the authorization server's token endpoint.
    #[must_use]
    pub fn token_endpoint(&self) -> &Url {
        match &self.token_endpoint {
            Some(u) => u,
            None => unreachable!(),
        }
    }

    /// URL of the authorization server's JWK Set document.
    #[must_use]
    pub fn jwks_uri(&self) -> &Url {
        match &self.jwks_uri {
            Some(u) => u,
            None => unreachable!(),
        }
    }

    /// JSON array containing a list of the OAuth 2.0 `response_type` values
    /// that this authorization server supports.
    #[must_use]
    pub fn response_types_supported(&self) -> &[OAuthAuthorizationEndpointResponseType] {
        match &self.response_types_supported {
            Some(u) => u,
            None => unreachable!(),
        }
    }

    /// JSON array containing a list of the Subject Identifier types that this
    /// OP supports.
    #[must_use]
    pub fn subject_types_supported(&self) -> &[SubjectType] {
        match &self.subject_types_supported {
            Some(u) => u,
            None => unreachable!(),
        }
    }

    /// JSON array containing a list of the JWS `alg` values supported by the OP
    /// for the ID Token.
    #[must_use]
    pub fn id_token_signing_alg_values_supported(&self) -> &[JsonWebSignatureAlg] {
        match &self.id_token_signing_alg_values_supported {
            Some(u) => u,
            None => unreachable!(),
        }
    }
}

impl Deref for VerifiedProviderMetadata {
    type Target = ProviderMetadata;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// All errors that can happen when verifying [`ProviderMetadata`]
#[derive(Debug, Error)]
pub enum ProviderMetadataVerificationError {
    /// The issuer is missing.
    #[error("issuer is missing")]
    MissingIssuer,

    /// The authorization endpoint is missing.
    #[error("authorization endpoint is missing")]
    MissingAuthorizationEndpoint,

    /// The token endpoint is missing.
    #[error("token endpoint is missing")]
    MissingTokenEndpoint,

    /// The JWK Set URI is missing.
    #[error("JWK Set URI is missing")]
    MissingJwksUri,

    /// The supported response types are missing.
    #[error("supported response types are missing")]
    MissingResponseTypesSupported,

    /// The supported subject types are missing.
    #[error("supported subject types are missing")]
    MissingSubjectTypesSupported,

    /// The supported ID token signing algorithm values are missing.
    #[error("supported ID token signing algorithm values are missing")]
    MissingIdTokenSigningAlgValuesSupported,

    /// The URL of the given field doesn't use a `https` scheme.
    #[error("{0}'s URL doesn't use a https scheme: {1}")]
    UrlNonHttpsScheme(&'static str, Url),

    /// The URL of the given field contains a query, but it's not allowed.
    #[error("{0}'s URL contains a query: {1}")]
    UrlWithQuery(&'static str, Url),

    /// The URL of the given field contains a fragment, but it's not allowed.
    #[error("{0}'s URL contains a fragment: {1}")]
    UrlWithFragment(&'static str, Url),

    /// The issuer URL doesn't match the one that was discovered.
    #[error("issuer URLs don't match")]
    IssuerUrlsDontMatch,

    /// `openid` is missing from the supported scopes.
    #[error("missing openid scope")]
    ScopesMissingOpenid,

    /// `code` is missing from the supported response types.
    #[error("missing `code` response type")]
    ResponseTypesMissingCode,

    /// `id_token` is missing from the supported response types.
    #[error("missing `id_token` response type")]
    ResponseTypesMissingIdToken,

    /// `id_token token` is missing from the supported response types.
    #[error("missing `id_token token` response type")]
    ResponseTypesMissingIdTokenToken,

    /// `authorization_code` is missing from the supported grant types.
    #[error("missing `authorization_code` grant type")]
    GrantTypesMissingAuthorizationCode,

    /// `implicit` is missing from the supported grant types.
    #[error("missing `implicit` grant type")]
    GrantTypesMissingImplicit,

    /// The given endpoint is missing auth signing algorithm values, but they
    /// are required because it supports at least one of the `client_secret_jwt`
    /// or `private_key_jwt` authentication methods.
    #[error("{0} missing auth signing algorithm values")]
    MissingAuthSigningAlgValues(&'static str),

    /// `none` is in the given endpoint's signing algorithm values, but is not
    /// allowed.
    #[error("{0} signing algorithm values contain `none`")]
    SigningAlgValuesWithNone(&'static str),

    /// `RS256` is missing from the given endpoint's signing algorithm values.
    #[error("missing RS256 in {0} signing algorithm values")]
    SigningAlgValuesMissingRs256(&'static str),
}

/// Possible extra restrictions on a URL.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ExtraUrlRestrictions {
    /// No extra restrictions.
    None,

    /// The URL must not contain a fragment.
    NoFragment,

    /// The URL must not contain a query or a fragment.
    NoQueryOrFragment,
}

impl ExtraUrlRestrictions {
    fn can_have_fragment(self) -> bool {
        self == Self::None
    }

    fn can_have_query(self) -> bool {
        self != Self::NoQueryOrFragment
    }
}

/// Validate the URL of the field with the given extra restrictions.
///
/// The basic restriction is that the URL must use the `https` scheme.
fn validate_url(
    field: &'static str,
    url: &Url,
    restrictions: ExtraUrlRestrictions,
) -> Result<(), ProviderMetadataVerificationError> {
    if url.scheme() != "https" {
        return Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(
            field,
            url.clone(),
        ));
    }

    if !restrictions.can_have_query() && url.query().is_some() {
        return Err(ProviderMetadataVerificationError::UrlWithQuery(
            field,
            url.clone(),
        ));
    }

    if !restrictions.can_have_fragment() && url.fragment().is_some() {
        return Err(ProviderMetadataVerificationError::UrlWithFragment(
            field,
            url.clone(),
        ));
    }

    Ok(())
}

/// Validate the algorithm values of the endpoint according to the
/// authentication methods.
///
/// The restrictions are:
/// - The algorithm values must not contain `none`,
/// - If the `client_secret_jwt` or `private_key_jwt` authentication methods are
///   supported, the values must be present.
fn validate_signing_alg_values_supported(
    endpoint: &'static str,
    values: &Option<Vec<JsonWebSignatureAlg>>,
    methods: &Option<Vec<OAuthClientAuthenticationMethod>>,
) -> Result<(), ProviderMetadataVerificationError> {
    if let Some(values) = values {
        if values.contains(&JsonWebSignatureAlg::None) {
            return Err(ProviderMetadataVerificationError::SigningAlgValuesWithNone(
                endpoint,
            ));
        }
    } else if methods.iter().flatten().any(|method| {
        matches!(
            method,
            OAuthClientAuthenticationMethod::ClientSecretJwt
                | OAuthClientAuthenticationMethod::PrivateKeyJwt
        )
    }) {
        return Err(ProviderMetadataVerificationError::MissingAuthSigningAlgValues(endpoint));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use mas_iana::{
        jose::JsonWebSignatureAlg,
        oauth::{OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod},
    };
    use url::Url;

    use super::{ProviderMetadata, ProviderMetadataVerificationError, SubjectType};

    fn valid_provider_metadata() -> (ProviderMetadata, Url) {
        let issuer = Url::parse("https://localhost").unwrap();
        let metadata = ProviderMetadata {
            issuer: Some(issuer.clone()),
            authorization_endpoint: Some(Url::parse("https://localhost/auth").unwrap()),
            token_endpoint: Some(Url::parse("https://localhost/token").unwrap()),
            jwks_uri: Some(Url::parse("https://localhost/jwks").unwrap()),
            response_types_supported: Some(vec![OAuthAuthorizationEndpointResponseType::Code]),
            subject_types_supported: Some(vec![SubjectType::Public]),
            id_token_signing_alg_values_supported: Some(vec![JsonWebSignatureAlg::Rs256]),
            ..Default::default()
        };

        (metadata, issuer)
    }

    #[test]
    fn validate_required_metadata() {
        let (metadata, issuer) = valid_provider_metadata();
        metadata.validate(&issuer).unwrap();
    }

    #[test]
    fn validate_issuer() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Missing
        metadata.issuer = None;
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingIssuer)
        );

        // Err - Wrong issuer
        metadata.issuer = Some(Url::parse("https://example.com").unwrap());
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::IssuerUrlsDontMatch)
        );

        // Err - Not https
        let issuer = Url::parse("http://localhost").unwrap();
        metadata.issuer = Some(issuer.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "issuer");
        assert_eq!(url, issuer);

        // Err - Query
        let issuer = Url::parse("https://localhost/?query").unwrap();
        metadata.issuer = Some(issuer.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlWithQuery(field, url)) => (field, url)
        );
        assert_eq!(field, "issuer");
        assert_eq!(url, issuer);

        // Err - Fragment
        let issuer = Url::parse("https://localhost/#fragment").unwrap();
        metadata.issuer = Some(issuer.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlWithFragment(field, url)) => (field, url)
        );
        assert_eq!(field, "issuer");
        assert_eq!(url, issuer);

        // Ok - Path
        let issuer = Url::parse("https://localhost/issuer1").unwrap();
        metadata.issuer = Some(issuer.clone());
        metadata.validate(&issuer).unwrap();
    }

    #[test]
    fn validate_authorization_endpoint() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Missing
        metadata.authorization_endpoint = None;
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingAuthorizationEndpoint)
        );

        // Err - Not https
        let endpoint = Url::parse("http://localhost/auth").unwrap();
        metadata.authorization_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "authorization_endpoint");
        assert_eq!(url, endpoint);

        // Err - Fragment
        let endpoint = Url::parse("https://localhost/auth#fragment").unwrap();
        metadata.authorization_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlWithFragment(field, url)) => (field, url)
        );
        assert_eq!(field, "authorization_endpoint");
        assert_eq!(url, endpoint);

        // Ok - Query
        metadata.authorization_endpoint = Some(Url::parse("https://localhost/auth?query").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    #[test]
    fn validate_token_endpoint() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Missing
        metadata.token_endpoint = None;
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingTokenEndpoint)
        );

        // Err - Not https
        let endpoint = Url::parse("http://localhost/token").unwrap();
        metadata.token_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "token_endpoint");
        assert_eq!(url, endpoint);

        // Err - Fragment
        let endpoint = Url::parse("https://localhost/token#fragment").unwrap();
        metadata.token_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlWithFragment(field, url)) => (field, url)
        );
        assert_eq!(field, "token_endpoint");
        assert_eq!(url, endpoint);

        // Ok - Query
        metadata.token_endpoint = Some(Url::parse("https://localhost/token?query").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    #[test]
    fn validate_jwks_uri() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Missing
        metadata.jwks_uri = None;
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingJwksUri)
        );

        // Err - Not https
        let endpoint = Url::parse("http://localhost/jwks").unwrap();
        metadata.jwks_uri = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "jwks_uri");
        assert_eq!(url, endpoint);

        // Ok - Query & fragment
        metadata.jwks_uri = Some(Url::parse("https://localhost/token?query#fragment").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    #[test]
    fn validate_registration_endpoint() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Not https
        let endpoint = Url::parse("http://localhost/registration").unwrap();
        metadata.registration_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "registration_endpoint");
        assert_eq!(url, endpoint);

        // Ok - Missing
        metadata.registration_endpoint = None;
        metadata.clone().validate(&issuer).unwrap();

        // Ok - Query & fragment
        metadata.registration_endpoint =
            Some(Url::parse("https://localhost/registration?query#fragment").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    #[test]
    fn validate_scopes_supported() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - No `openid`
        metadata.scopes_supported = Some(vec!["custom".to_owned()]);
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::ScopesMissingOpenid)
        );

        // Ok - Missing
        metadata.scopes_supported = None;
        metadata.clone().validate(&issuer).unwrap();

        // Ok - With `openid`
        metadata.scopes_supported = Some(vec!["openid".to_owned(), "custom".to_owned()]);
        metadata.validate(&issuer).unwrap();
    }

    #[test]
    fn validate_response_types_supported() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Missing
        metadata.response_types_supported = None;
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingResponseTypesSupported)
        );

        // Ok - Present
        metadata.response_types_supported =
            Some(vec![OAuthAuthorizationEndpointResponseType::Code]);
        metadata.validate(&issuer).unwrap();
    }

    #[test]
    fn validate_token_endpoint_signing_alg_values_supported() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Ok - Missing
        metadata.token_endpoint_auth_signing_alg_values_supported = None;
        metadata.token_endpoint_auth_methods_supported = None;
        metadata.clone().validate(&issuer).unwrap();

        // Err - With `none`
        metadata.token_endpoint_auth_signing_alg_values_supported =
            Some(vec![JsonWebSignatureAlg::None]);
        let endpoint = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::SigningAlgValuesWithNone(endpoint)) => endpoint
        );
        assert_eq!(endpoint, "token_endpoint");

        // Ok - Other signing alg values.
        metadata.token_endpoint_auth_signing_alg_values_supported =
            Some(vec![JsonWebSignatureAlg::Rs256, JsonWebSignatureAlg::EdDsa]);
        metadata.clone().validate(&issuer).unwrap();

        // Err - `client_secret_jwt` without signing alg values.
        metadata.token_endpoint_auth_methods_supported =
            Some(vec![OAuthClientAuthenticationMethod::ClientSecretJwt]);
        metadata.token_endpoint_auth_signing_alg_values_supported = None;
        let endpoint = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingAuthSigningAlgValues(endpoint)) => endpoint
        );
        assert_eq!(endpoint, "token_endpoint");

        // Ok - `client_secret_jwt` with signing alg values.
        metadata.token_endpoint_auth_signing_alg_values_supported =
            Some(vec![JsonWebSignatureAlg::Rs256]);
        metadata.clone().validate(&issuer).unwrap();

        // Err - `private_key_jwt` without signing alg values.
        metadata.token_endpoint_auth_methods_supported =
            Some(vec![OAuthClientAuthenticationMethod::PrivateKeyJwt]);
        metadata.token_endpoint_auth_signing_alg_values_supported = None;
        let endpoint = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingAuthSigningAlgValues(endpoint)) => endpoint
        );
        assert_eq!(endpoint, "token_endpoint");

        // Ok - `private_key_jwt` with signing alg values.
        metadata.token_endpoint_auth_signing_alg_values_supported =
            Some(vec![JsonWebSignatureAlg::Rs256]);
        metadata.clone().validate(&issuer).unwrap();

        // Ok - Other auth methods without signing alg values.
        metadata.token_endpoint_auth_methods_supported = Some(vec![
            OAuthClientAuthenticationMethod::ClientSecretBasic,
            OAuthClientAuthenticationMethod::ClientSecretPost,
        ]);
        metadata.token_endpoint_auth_signing_alg_values_supported = None;
        metadata.validate(&issuer).unwrap();
    }

    #[test]
    fn validate_revocation_endpoint() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Ok - Missing
        metadata.revocation_endpoint = None;
        metadata.clone().validate(&issuer).unwrap();

        // Err - Not https
        let endpoint = Url::parse("http://localhost/revocation").unwrap();
        metadata.revocation_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "revocation_endpoint");
        assert_eq!(url, endpoint);

        // Err - Fragment
        let endpoint = Url::parse("https://localhost/revocation#fragment").unwrap();
        metadata.revocation_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlWithFragment(field, url)) => (field, url)
        );
        assert_eq!(field, "revocation_endpoint");
        assert_eq!(url, endpoint);

        // Ok - Query
        metadata.revocation_endpoint =
            Some(Url::parse("https://localhost/revocation?query").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    #[test]
    fn validate_revocation_endpoint_signing_alg_values_supported() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Only check that this field is validated, algorithm checks are already
        // tested for the token endpoint.

        // Ok - Missing
        metadata.revocation_endpoint_auth_signing_alg_values_supported = None;
        metadata.revocation_endpoint_auth_methods_supported = None;
        metadata.clone().validate(&issuer).unwrap();

        // Err - With `none`
        metadata.revocation_endpoint_auth_signing_alg_values_supported =
            Some(vec![JsonWebSignatureAlg::None]);
        let endpoint = assert_matches!(
            metadata.validate(&issuer),
            Err(ProviderMetadataVerificationError::SigningAlgValuesWithNone(endpoint)) => endpoint
        );
        assert_eq!(endpoint, "revocation_endpoint");
    }

    #[test]
    fn validate_introspection_endpoint() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Ok - Missing
        metadata.introspection_endpoint = None;
        metadata.clone().validate(&issuer).unwrap();

        // Err - Not https
        let endpoint = Url::parse("http://localhost/introspection").unwrap();
        metadata.introspection_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "introspection_endpoint");
        assert_eq!(url, endpoint);

        // Ok - Query & Fragment
        metadata.introspection_endpoint =
            Some(Url::parse("https://localhost/introspection?query#fragment").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    #[test]
    fn validate_introspection_endpoint_signing_alg_values_supported() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Only check that this field is validated, algorithm checks are already
        // tested for the token endpoint.

        // Ok - Missing
        metadata.introspection_endpoint_auth_signing_alg_values_supported = None;
        metadata.introspection_endpoint_auth_methods_supported = None;
        metadata.clone().validate(&issuer).unwrap();

        // Err - With `none`
        metadata.introspection_endpoint_auth_signing_alg_values_supported =
            Some(vec![JsonWebSignatureAlg::None]);
        let endpoint = assert_matches!(
            metadata.validate(&issuer),
            Err(ProviderMetadataVerificationError::SigningAlgValuesWithNone(endpoint)) => endpoint
        );
        assert_eq!(endpoint, "introspection_endpoint");
    }

    #[test]
    fn validate_userinfo_endpoint() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Ok - Missing
        metadata.userinfo_endpoint = None;
        metadata.clone().validate(&issuer).unwrap();

        // Err - Not https
        let endpoint = Url::parse("http://localhost/userinfo").unwrap();
        metadata.userinfo_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "userinfo_endpoint");
        assert_eq!(url, endpoint);

        // Ok - Query & Fragment
        metadata.userinfo_endpoint =
            Some(Url::parse("https://localhost/userinfo?query#fragment").unwrap());
        metadata.validate(&issuer).unwrap();
    }

    #[test]
    fn validate_subject_types_supported() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Missing
        metadata.subject_types_supported = None;
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingSubjectTypesSupported)
        );

        // Ok - Present
        metadata.subject_types_supported = Some(vec![SubjectType::Public, SubjectType::Pairwise]);
        metadata.validate(&issuer).unwrap();
    }

    #[test]
    fn validate_id_token_signing_alg_values_supported() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Err - Missing
        metadata.id_token_signing_alg_values_supported = None;
        assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::MissingIdTokenSigningAlgValuesSupported)
        );

        // Err - No RS256
        metadata.id_token_signing_alg_values_supported = Some(vec![JsonWebSignatureAlg::EdDsa]);
        let endpoint = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::SigningAlgValuesMissingRs256(endpoint)) => endpoint
        );
        assert_eq!(endpoint, "id_token");

        // Ok - With RS256
        metadata.id_token_signing_alg_values_supported =
            Some(vec![JsonWebSignatureAlg::Rs256, JsonWebSignatureAlg::EdDsa]);
        metadata.validate(&issuer).unwrap();
    }

    #[test]
    fn validate_pushed_authorization_request_endpoint() {
        let (mut metadata, issuer) = valid_provider_metadata();

        // Ok - Missing
        metadata.pushed_authorization_request_endpoint = None;
        metadata.clone().validate(&issuer).unwrap();

        // Err - Not https
        let endpoint = Url::parse("http://localhost/par").unwrap();
        metadata.pushed_authorization_request_endpoint = Some(endpoint.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(&issuer),
            Err(ProviderMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "pushed_authorization_request_endpoint");
        assert_eq!(url, endpoint);

        // Ok - Query & Fragment
        metadata.pushed_authorization_request_endpoint =
            Some(Url::parse("https://localhost/par?query#fragment").unwrap());
        metadata.validate(&issuer).unwrap();
    }
}
