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

use std::{collections::HashMap, marker::PhantomData, ops::Deref};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClaimError {
    #[error("missing claim {0:?}")]
    MissingClaim(&'static str),

    #[error("invalid claim {0:?}")]
    InvalidClaim(&'static str),

    #[error("could not validate claim {claim:?}")]
    ValidationError {
        claim: &'static str,
        #[source]
        source: anyhow::Error,
    },
}

pub trait Validator<T> {
    fn validate(&self, value: &T) -> Result<(), anyhow::Error>;
}

impl<T> Validator<T> for () {
    fn validate(&self, _value: &T) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

pub struct Claim<T, V = ()> {
    claim: &'static str,
    t: PhantomData<T>,
    v: PhantomData<V>,
}

impl<T, V> Claim<T, V> {
    #[must_use]
    pub const fn new(claim: &'static str) -> Self {
        Self {
            claim,
            t: PhantomData,
            v: PhantomData,
        }
    }

    pub fn insert<I>(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
        value: I,
    ) -> Result<(), ClaimError>
    where
        I: Into<T>,
        T: Serialize,
    {
        let value = value.into();
        let value: serde_json::Value =
            serde_json::to_value(&value).map_err(|_| ClaimError::InvalidClaim(self.claim))?;
        claims.insert(self.claim.to_string(), value);

        Ok(())
    }

    pub fn extract_required(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
    ) -> Result<T, ClaimError>
    where
        T: DeserializeOwned,
        V: Default + Validator<T>,
    {
        let validator = V::default();
        self.extract_required_with_options(claims, validator)
    }

    pub fn extract_required_with_options<I>(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
        validator: I,
    ) -> Result<T, ClaimError>
    where
        T: DeserializeOwned,
        I: Into<V>,
        V: Validator<T>,
    {
        let validator: V = validator.into();
        let claim = claims
            .remove(self.claim)
            .ok_or(ClaimError::MissingClaim(self.claim))?;

        let res =
            serde_json::from_value(claim).map_err(|_| ClaimError::InvalidClaim(self.claim))?;
        validator
            .validate(&res)
            .map_err(|source| ClaimError::ValidationError {
                claim: self.claim,
                source,
            })?;
        Ok(res)
    }

    pub fn extract_optional(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
    ) -> Result<Option<T>, ClaimError>
    where
        T: DeserializeOwned,
        V: Default + Validator<T>,
    {
        let validator = V::default();
        self.extract_optional_with_options(claims, validator)
    }

    pub fn extract_optional_with_options<I>(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
        validator: I,
    ) -> Result<Option<T>, ClaimError>
    where
        T: DeserializeOwned,
        I: Into<V>,
        V: Validator<T>,
    {
        match self.extract_required_with_options(claims, validator) {
            Ok(v) => Ok(Some(v)),
            Err(ClaimError::MissingClaim(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimeOptions {
    when: Option<chrono::DateTime<chrono::Utc>>,
    leeway: chrono::Duration,
}

impl Default for TimeOptions {
    fn default() -> Self {
        Self {
            when: None,
            leeway: chrono::Duration::minutes(5),
        }
    }
}

impl TimeOptions {
    #[must_use]
    pub fn new(when: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            when: Some(when),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn freeze(mut self) -> Self {
        self.when = Some(chrono::Utc::now());
        self
    }

    #[must_use]
    pub fn leeway(mut self, leeway: chrono::Duration) -> Self {
        self.leeway = leeway;
        self
    }

    fn when(&self) -> chrono::DateTime<chrono::Utc> {
        self.when.unwrap_or_else(chrono::Utc::now)
    }
}

#[derive(Debug, Clone, Default)]
pub struct TimeNotAfter(TimeOptions);

impl Validator<Timestamp> for TimeNotAfter {
    fn validate(&self, value: &Timestamp) -> Result<(), anyhow::Error> {
        if self.0.when() <= value.0 + self.0.leeway {
            Ok(())
        } else {
            Err(anyhow::anyhow!("current time is too far away"))
        }
    }
}

impl From<TimeOptions> for TimeNotAfter {
    fn from(opt: TimeOptions) -> Self {
        Self(opt)
    }
}

impl From<&TimeOptions> for TimeNotAfter {
    fn from(opt: &TimeOptions) -> Self {
        opt.clone().into()
    }
}

#[derive(Debug, Clone, Default)]
pub struct TimeNotBefore(TimeOptions);

impl Validator<Timestamp> for TimeNotBefore {
    fn validate(&self, value: &Timestamp) -> Result<(), anyhow::Error> {
        if self.0.when() >= value.0 - self.0.leeway {
            Ok(())
        } else {
            Err(anyhow::anyhow!("current time is too far before"))
        }
    }
}

impl From<TimeOptions> for TimeNotBefore {
    fn from(opt: TimeOptions) -> Self {
        Self(opt)
    }
}

impl From<&TimeOptions> for TimeNotBefore {
    fn from(opt: &TimeOptions) -> Self {
        opt.clone().into()
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(transparent)]
pub struct Timestamp(#[serde(with = "chrono::serde::ts_seconds")] chrono::DateTime<chrono::Utc>);

impl Deref for Timestamp {
    type Target = chrono::DateTime<chrono::Utc>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<chrono::DateTime<chrono::Utc>> for Timestamp {
    fn from(value: chrono::DateTime<chrono::Utc>) -> Self {
        Timestamp(value)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(
    transparent,
    bound(serialize = "T: Serialize", deserialize = "T: Deserialize<'de>")
)]
pub struct OneOrMany<T>(
    // serde_as seems to not work properly with #[serde(transparent)]
    // We have use plain old #[serde(with = ...)] with serde_with's utilities, which is a bit
    // verbose but works
    #[serde(
        with = "serde_with::As::<serde_with::OneOrMany<serde_with::Same, serde_with::formats::PreferOne>>"
    )]
    Vec<T>,
);

impl<T> Deref for OneOrMany<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<Vec<T>> for OneOrMany<T> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}

impl<T> From<T> for OneOrMany<T> {
    fn from(value: T) -> Self {
        Self(vec![value])
    }
}

/// Claims defined in RFC7519 sec. 4.1
/// <https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1>
mod rfc7519 {
    use super::{Claim, OneOrMany, TimeNotAfter, TimeNotBefore, Timestamp};

    pub const ISS: Claim<String> = Claim::new("iss");
    pub const SUB: Claim<String> = Claim::new("sub");
    pub const AUD: Claim<OneOrMany<String>> = Claim::new("aud");
    pub const NBF: Claim<Timestamp, TimeNotBefore> = Claim::new("nbf");
    pub const EXP: Claim<Timestamp, TimeNotAfter> = Claim::new("exp");
    pub const IAT: Claim<Timestamp, TimeNotBefore> = Claim::new("iat");
    pub const JTI: Claim<String> = Claim::new("jti");
}

/// Claims defined in OIDC.Core sec. 2 and sec. 5.1
/// <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>
/// <https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims>
mod oidc_core {
    use url::Url;

    use super::{Claim, Timestamp};

    pub const AUTH_TIME: Claim<Timestamp> = Claim::new("auth_time");
    pub const NONCE: Claim<String> = Claim::new("nonce");
    pub const AT_HASH: Claim<String> = Claim::new("at_hash");
    pub const C_HASH: Claim<String> = Claim::new("c_hash");

    pub const NAME: Claim<String> = Claim::new("name");
    pub const GIVEN_NAME: Claim<String> = Claim::new("given_name");
    pub const FAMILY_NAME: Claim<String> = Claim::new("family_name");
    pub const MIDDLE_NAME: Claim<String> = Claim::new("middle_name");
    pub const NICKNAME: Claim<String> = Claim::new("nickname");
    pub const PREFERRED_USERNAME: Claim<String> = Claim::new("preferred_username");
    pub const PROFILE: Claim<Url> = Claim::new("profile");
    pub const PICTURE: Claim<Url> = Claim::new("picture");
    pub const WEBSITE: Claim<Url> = Claim::new("website");
    // TODO: email type?
    pub const EMAIL: Claim<String> = Claim::new("email");
    pub const EMAIL_VERIFIED: Claim<bool> = Claim::new("email_verified");
    pub const GENDER: Claim<String> = Claim::new("gender");
    // TODO: date type
    pub const BIRTHDATE: Claim<String> = Claim::new("birthdate");
    // TODO: timezone type
    pub const ZONEINFO: Claim<String> = Claim::new("zoneinfo");
    // TODO: locale type
    pub const LOCALE: Claim<String> = Claim::new("locale");
    // TODO: phone number type
    pub const PHONE_NUMBER: Claim<String> = Claim::new("phone_number");
    pub const PHONE_NUMBER_VERIFIED: Claim<bool> = Claim::new("phone_number_verified");
    // TODO: pub const ADDRESS: Claim<Timestamp> = Claim::new("address");
    pub const UPDATED_AT: Claim<Timestamp> = Claim::new("updated_at");
}

pub use self::{oidc_core::*, rfc7519::*};

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn timestamp_serde() {
        let datetime = Timestamp(
            chrono::Utc
                .ymd_opt(2018, 1, 18)
                .and_hms_opt(1, 30, 22)
                .unwrap(),
        );
        let timestamp = serde_json::Value::Number(1_516_239_022.into());

        assert_eq!(datetime, serde_json::from_value(timestamp.clone()).unwrap());
        assert_eq!(timestamp, serde_json::to_value(&datetime).unwrap());
    }

    #[test]
    fn one_or_many_serde() {
        let one = OneOrMany(vec!["one".to_string()]);
        let many = OneOrMany(vec!["one".to_string(), "two".to_string()]);

        assert_eq!(
            one,
            serde_json::from_value(serde_json::json!("one")).unwrap()
        );
        assert_eq!(
            one,
            serde_json::from_value(serde_json::json!(["one"])).unwrap()
        );
        assert_eq!(
            many,
            serde_json::from_value(serde_json::json!(["one", "two"])).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&one).unwrap(),
            serde_json::json!("one")
        );
        assert_eq!(
            serde_json::to_value(&many).unwrap(),
            serde_json::json!(["one", "two"])
        );
    }

    #[test]
    fn extract_claims() {
        let now = chrono::Utc
            .ymd_opt(2018, 1, 18)
            .and_hms_opt(1, 30, 22)
            .unwrap();
        let expiration = now + chrono::Duration::minutes(5);
        let time_options = TimeOptions::new(now).leeway(chrono::Duration::zero());

        let claims = serde_json::json!({
            "iss": "https://foo.com",
            "sub": "johndoe",
            "aud": ["abcd-efgh"],
            "iat": 1_516_239_022,
            "nbf": 1_516_239_022,
            "exp": 1_516_239_322,
            "jti": "1122-3344-5566-7788",
        });
        let mut claims = serde_json::from_value(claims).unwrap();

        let iss = ISS.extract_required(&mut claims).unwrap();
        let sub = SUB.extract_optional(&mut claims).unwrap();
        let aud = AUD.extract_optional(&mut claims).unwrap();
        let nbf = NBF
            .extract_optional_with_options(&mut claims, &time_options)
            .unwrap();
        let exp = EXP
            .extract_optional_with_options(&mut claims, &time_options)
            .unwrap();
        let iat = IAT
            .extract_optional_with_options(&mut claims, &time_options)
            .unwrap();
        let jti = JTI.extract_optional(&mut claims).unwrap();

        assert_eq!(iss, "https://foo.com".to_string());
        assert_eq!(sub, Some("johndoe".to_string()));
        assert_eq!(aud.as_deref(), Some(&vec!["abcd-efgh".to_string()]));
        assert_eq!(iat.as_deref(), Some(&now));
        assert_eq!(nbf.as_deref(), Some(&now));
        assert_eq!(exp.as_deref(), Some(&expiration));
        assert_eq!(jti, Some("1122-3344-5566-7788".to_string()));

        assert!(claims.is_empty());
    }

    #[test]
    fn time_validation() {
        let now = chrono::Utc
            .ymd_opt(2018, 1, 18)
            .and_hms_opt(1, 30, 22)
            .unwrap();

        let claims = serde_json::json!({
            "iat": 1_516_239_022,
            "nbf": 1_516_239_022,
            "exp": 1_516_239_322,
        });
        let claims: HashMap<String, serde_json::Value> = serde_json::from_value(claims).unwrap();

        // Everything should be fine at this point, the claims iat & nbf == now
        {
            let mut claims = claims.clone();

            // so no leeway should be fine as well here
            let time_options = TimeOptions::new(now).leeway(chrono::Duration::zero());
            assert!(IAT
                .extract_required_with_options(&mut claims, &time_options)
                .is_ok());
            assert!(NBF
                .extract_required_with_options(&mut claims, &time_options)
                .is_ok());
            assert!(EXP
                .extract_required_with_options(&mut claims, &time_options)
                .is_ok());
        }

        // Let's go back in time a bit
        let now = now - chrono::Duration::minutes(1);

        {
            // There is now a time variance between the two parties...
            let mut claims = claims.clone();

            // but no time variance is allowed. "iat" and "nbf" validation will fail
            let time_options = TimeOptions::new(now).leeway(chrono::Duration::zero());
            assert!(matches!(
                IAT.extract_required_with_options(&mut claims, &time_options),
                Err(ClaimError::ValidationError { claim: "iat", .. }),
            ));
            assert!(matches!(
                NBF.extract_required_with_options(&mut claims, &time_options),
                Err(ClaimError::ValidationError { claim: "nbf", .. }),
            ));
            assert!(EXP
                .extract_required_with_options(&mut claims, &time_options)
                .is_ok());
        }

        {
            // This time, there is a two minute leeway, they all should be fine
            let mut claims = claims.clone();

            // but no time variance is allowed. "iat" and "nbf" validation will fail
            let time_options = TimeOptions::new(now).leeway(chrono::Duration::minutes(2));
            assert!(IAT
                .extract_required_with_options(&mut claims, &time_options)
                .is_ok());
            assert!(NBF
                .extract_required_with_options(&mut claims, &time_options)
                .is_ok());
            assert!(EXP
                .extract_required_with_options(&mut claims, &time_options)
                .is_ok());
        }

        // Let's wait some time so it expires
        let now = now + chrono::Duration::minutes(1 + 6);

        {
            // At this point, the claims expired one minute ago
            let mut claims = claims.clone();

            // but no time variance is allowed. "exp" validation will fail
            let time_options = TimeOptions::new(now).leeway(chrono::Duration::zero());
            assert!(IAT
                .extract_required_with_options(&mut claims, &time_options)
                .is_ok());
            assert!(NBF
                .extract_required_with_options(&mut claims, &time_options)
                .is_ok());
            assert!(matches!(
                EXP.extract_required_with_options(&mut claims, &time_options),
                Err(ClaimError::ValidationError { claim: "exp", .. }),
            ));
        }

        {
            let mut claims = claims;

            // Same, but with a 2 minutes leeway should be fine then
            let time_options = TimeOptions::new(now).leeway(chrono::Duration::minutes(2));
            assert!(IAT
                .extract_required_with_options(&mut claims, &time_options)
                .is_ok());
            assert!(NBF
                .extract_required_with_options(&mut claims, &time_options)
                .is_ok());
            assert!(EXP
                .extract_required_with_options(&mut claims, &time_options)
                .is_ok());
        }
    }

    #[test]
    fn invalid_claims() {
        let now = chrono::Utc
            .ymd_opt(2018, 1, 18)
            .and_hms_opt(1, 30, 22)
            .unwrap();
        let time_options = TimeOptions::new(now).leeway(chrono::Duration::zero());

        let claims = serde_json::json!({
            "iss": 123,
            "sub": 456,
            "aud": 789,
            "iat": "123",
            "nbf": "456",
            "exp": "789",
            "jti": 123,
        });
        let mut claims = serde_json::from_value(claims).unwrap();

        assert!(matches!(
            ISS.extract_required(&mut claims),
            Err(ClaimError::InvalidClaim("iss"))
        ));
        assert!(matches!(
            SUB.extract_required(&mut claims),
            Err(ClaimError::InvalidClaim("sub"))
        ));
        assert!(matches!(
            AUD.extract_required(&mut claims),
            Err(ClaimError::InvalidClaim("aud"))
        ));
        assert!(matches!(
            NBF.extract_required_with_options(&mut claims, &time_options),
            Err(ClaimError::InvalidClaim("nbf"))
        ));
        assert!(matches!(
            EXP.extract_required_with_options(&mut claims, &time_options),
            Err(ClaimError::InvalidClaim("exp"))
        ));
        assert!(matches!(
            IAT.extract_required_with_options(&mut claims, &time_options),
            Err(ClaimError::InvalidClaim("iat"))
        ));
        assert!(matches!(
            JTI.extract_required(&mut claims),
            Err(ClaimError::InvalidClaim("jti"))
        ));
    }

    #[test]
    fn missing_claims() {
        // Empty claim set
        let mut claims = HashMap::new();

        assert!(matches!(
            ISS.extract_required(&mut claims),
            Err(ClaimError::MissingClaim("iss"))
        ));
        assert!(matches!(
            SUB.extract_required(&mut claims),
            Err(ClaimError::MissingClaim("sub"))
        ));
        assert!(matches!(
            AUD.extract_required(&mut claims),
            Err(ClaimError::MissingClaim("aud"))
        ));

        assert!(matches!(ISS.extract_optional(&mut claims), Ok(None)));
        assert!(matches!(SUB.extract_optional(&mut claims), Ok(None)));
        assert!(matches!(AUD.extract_optional(&mut claims), Ok(None)));
    }
}
