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

use std::{convert::Infallible, sync::Arc};

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
    TypedHeader,
};
use mas_axum_utils::language_detection::AcceptLanguage;
use mas_i18n::{DataLocale, Translator};

pub struct PreferredLanguage(pub DataLocale);

#[async_trait]
impl<S> FromRequestParts<S> for PreferredLanguage
where
    S: Send + Sync,
    Arc<Translator>: FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let translator: Arc<Translator> = FromRef::from_ref(state);
        let accept_language: Option<TypedHeader<AcceptLanguage>> =
            FromRequestParts::from_request_parts(parts, state).await?;
        let supported_language = translator.available_locales();

        let locale = accept_language
            .and_then(|TypedHeader(accept_language)| {
                accept_language.iter().find_map(|lang| {
                    let locale: DataLocale = lang.into();
                    supported_language.contains(&&locale).then_some(locale)
                })
            })
            .unwrap_or("en".parse().unwrap());

        Ok(PreferredLanguage(locale))
    }
}
