use std::collections::HashSet;

use serde::Serialize;
use url::Url;

use crate::requests::{GrantType, ResponseMode, ResponseType};

// TODO: https://datatracker.ietf.org/doc/html/rfc8414#section-2
#[derive(Serialize)]
pub struct Metadata {
    /// The authorization server's issuer identifier, which is a URL that uses the "https" scheme
    /// and has no query or fragment components.
    pub issuer: Url,

    /// URL of the authorization server's authorization endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<Url>,

    /// URL of the authorization server's token endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<Url>,

    /// URL of the authorization server's JWK Set document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<Url>,

    /// URL of the authorization server's OAuth 2.0 Dynamic Client Registration endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<Url>,

    /// JSON array containing a list of the OAuth 2.0 "scope" values that this authorization server
    /// supports.
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub scopes_supported: HashSet<String>,

    /// JSON array containing a list of the OAuth 2.0 "response_type" values that this
    /// authorization server supports.
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub response_types_supported: HashSet<ResponseType>,

    /// JSON array containing a list of the OAuth 2.0 "response_mode" values that this
    /// authorization server supports, as specified in "OAuth 2.0 Multiple Response Type Encoding
    /// Practices".
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub response_modes_supported: HashSet<ResponseMode>,

    /// JSON array containing a list of the OAuth 2.0 grant type values that this authorization
    /// server supports.
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub grant_types_supported: HashSet<GrantType>,
}
