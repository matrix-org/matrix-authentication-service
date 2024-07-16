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
};
use axum_extra::typed_header::TypedHeader;
use mas_axum_utils::language_detection::AcceptLanguage;
use mas_i18n::{locale, DataLocale, Translator};

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

        let iter = accept_language
            .iter()
            .flat_map(|TypedHeader(accept_language)| accept_language.iter())
            .flat_map(|lang| {
                let lang = DataLocale::from(lang);
                // XXX: this is hacky as we may want to actually maintain proper language
                // aliases at some point, but `zh-CN` doesn't fallback
                // automatically to `zh-Hans`, so we insert it manually here.
                // For some reason, `zh-TW` does fallback to `zh-Hant` correctly.
                if lang == locale!("zh-CN").into() {
                    vec![lang, locale!("zh-Hans").into()]
                } else {
                    vec![lang]
                }
            });

        let locale = translator.choose_locale(iter);

        Ok(PreferredLanguage(locale))
    }
}
