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

use std::{convert::Infallible, error::Error};

use async_trait::async_trait;
use axum::{
    body::{HttpBody, StreamBody},
    extract::{Extension, FromRequest, RequestParts},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use futures_util::FutureExt;
use headers::{ContentType, HeaderMapExt};
use mas_templates::{ErrorContext, Templates};
use sqlx::PgPool;

struct DatabaseConnection(sqlx::pool::PoolConnection<sqlx::Postgres>);

#[async_trait]
impl<B> FromRequest<B> for DatabaseConnection
where
    B: Send,
{
    type Rejection = FancyError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(templates) = Extension::<Templates>::from_request(req)
            .await
            .map_err(internal_error)?;

        let Extension(pool) = Extension::<PgPool>::from_request(req)
            .await
            .map_err(fancy_error(templates))?;

        let conn = pool.acquire().await.map_err(internal_error)?;

        Ok(Self(conn))
    }
}

pub fn fancy_error<E: Error + 'static>(templates: Templates) -> impl Fn(E) -> FancyError {
    move |error: E| FancyError {
        templates: Some(templates.clone()),
        error: Box::new(error),
    }
}

pub fn internal_error<E: Error + 'static>(error: E) -> FancyError
where
    E: Error,
{
    FancyError {
        templates: None,
        error: Box::new(error),
    }
}

pub struct FancyError {
    templates: Option<Templates>,
    error: Box<dyn Error>,
}

impl IntoResponse for FancyError {
    fn into_response(self) -> Response {
        let error = format!("{}", self.error);
        let context = ErrorContext::new().with_description(error.clone());
        let body = match self.templates {
            Some(templates) => {
                let stream = (async move {
                    Ok::<_, Infallible>(match templates.render_error(&context).await {
                        Ok(s) => s,
                        Err(_e) => "failed to render error template".to_string(),
                    })
                })
                .into_stream();

                StreamBody::new(stream).boxed_unsync()
            }
            None => axum::body::Full::from(error)
                .map_err(|_e| unreachable!())
                .boxed_unsync(),
        };

        let mut res = Response::new(body);
        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        res.headers_mut().typed_insert(ContentType::html());
        res
    }
}

