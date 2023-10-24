use std::sync::Arc;

use minijinja::{value::StructObject, Value};

/// Site branding information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteBranding {
    server_name: Arc<str>,
    service_name: Option<Arc<str>>,
    policy_uri: Option<Arc<str>>,
    tos_uri: Option<Arc<str>>,
    imprint: Option<Arc<str>>,
    logo_uri: Option<Arc<str>>,
}

impl SiteBranding {
    /// Create a new site branding based on the given server name.
    #[must_use]
    pub fn new(server_name: impl Into<Arc<str>>) -> Self {
        Self {
            server_name: server_name.into(),
            service_name: None,
            policy_uri: None,
            tos_uri: None,
            imprint: None,
            logo_uri: None,
        }
    }

    /// Set the service name.
    #[must_use]
    pub fn with_service_name(mut self, service_name: impl Into<Arc<str>>) -> Self {
        self.service_name = Some(service_name.into());
        self
    }

    /// Set the policy URI.
    #[must_use]
    pub fn with_policy_uri(mut self, policy_uri: impl Into<Arc<str>>) -> Self {
        self.policy_uri = Some(policy_uri.into());
        self
    }

    /// Set the terms of service URI.
    #[must_use]
    pub fn with_tos_uri(mut self, tos_uri: impl Into<Arc<str>>) -> Self {
        self.tos_uri = Some(tos_uri.into());
        self
    }

    /// Set the imprint.
    #[must_use]
    pub fn with_imprint(mut self, imprint: impl Into<Arc<str>>) -> Self {
        self.imprint = Some(imprint.into());
        self
    }

    /// Set the logo URI.
    #[must_use]
    pub fn with_logo_uri(mut self, logo_uri: impl Into<Arc<str>>) -> Self {
        self.logo_uri = Some(logo_uri.into());
        self
    }
}

impl StructObject for SiteBranding {
    fn get_field(&self, name: &str) -> Option<Value> {
        match name {
            "server_name" => Some(self.server_name.clone().into()),
            "service_name" => self.service_name.clone().map(Value::from),
            "policy_uri" => self.policy_uri.clone().map(Value::from),
            "tos_uri" => self.tos_uri.clone().map(Value::from),
            "imprint" => self.imprint.clone().map(Value::from),
            "logo_uri" => self.logo_uri.clone().map(Value::from),
            _ => None,
        }
    }

    fn static_fields(&self) -> Option<&'static [&'static str]> {
        Some(&[
            "server_name",
            "service_name",
            "policy_uri",
            "tos_uri",
            "imprint",
            "logo_uri",
        ])
    }
}
