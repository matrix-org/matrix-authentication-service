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

use std::convert::Infallible;

use anyhow::{bail, Context};
use bytes::{Buf, Bytes};
use headers::{ContentType, HeaderMapExt};
use http::{header::ACCEPT, HeaderValue, Request, Response, StatusCode};
use mas_http::{
    BodyToBytesResponseLayer, BytesToBodyRequestLayer, CatchHttpCodesLayer,
    FormUrlencodedRequestLayer, JsonRequestLayer, JsonResponseLayer,
};
use serde::Deserialize;
use thiserror::Error;
use tower::{service_fn, Layer, ServiceExt};

#[derive(Debug, Error, Deserialize)]
#[error("Error code in response: {error}")]
struct Error {
    error: String,
}

#[tokio::test]
async fn test_http_errors() {
    async fn handle<B>(_: Request<B>) -> Result<Response<String>, Infallible> {
        let mut res = Response::new(r#"{"error": "invalid_request"}"#.to_owned());
        *res.status_mut() = StatusCode::BAD_REQUEST;

        Ok(res)
    }

    fn mapper(response: Response<Bytes>) -> Error {
        serde_json::from_reader(response.into_body().reader()).unwrap()
    }

    let layer = (
        CatchHttpCodesLayer::exact(StatusCode::BAD_REQUEST, mapper),
        BodyToBytesResponseLayer,
    );
    let svc = layer.layer(service_fn(handle));

    let request = Request::new(hyper::Body::empty());

    let res = svc.oneshot(request).await;
    let err = res.expect_err("the request should fail");
    assert_eq!(err.status_code(), Some(StatusCode::BAD_REQUEST));
}

#[tokio::test]
async fn test_json_request_body() {
    async fn handle<B>(request: Request<B>) -> Result<Response<hyper::Body>, anyhow::Error>
    where
        B: http_body::Body + Send,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        if request
            .headers()
            .typed_get::<ContentType>()
            .context("Missing Content-Type header")?
            != ContentType::json()
        {
            bail!("Content-Type header is not application/json")
        }

        let bytes = hyper::body::to_bytes(request.into_body()).await?;
        if bytes.to_vec() != br#"{"hello":"world"}"#.to_vec() {
            bail!("Body mismatch")
        }

        let res = Response::new(hyper::Body::empty());
        Ok(res)
    }

    let layer = (JsonRequestLayer::default(), BytesToBodyRequestLayer);
    let svc = layer.layer(service_fn(handle));

    let request = Request::new(serde_json::json!({"hello": "world"}));

    let res = svc.oneshot(request).await;
    res.expect("the request should succeed");
}

#[tokio::test]
async fn test_json_response_body() {
    async fn handle<B>(request: Request<B>) -> Result<Response<String>, anyhow::Error> {
        if request
            .headers()
            .get(ACCEPT)
            .context("Missing Accept header")?
            != HeaderValue::from_static("application/json")
        {
            bail!("Accept header is not application/json")
        }

        let res = Response::new(r#"{"hello": "world"}"#.to_owned());
        Ok(res)
    }

    let layer = (JsonResponseLayer::default(), BodyToBytesResponseLayer);
    let svc = layer.layer(service_fn(handle));

    let request = Request::new(hyper::Body::empty());

    let res = svc.oneshot(request).await;
    let response = res.expect("the request to succeed");
    let body: serde_json::Value = response.into_body();
    assert_eq!(body, serde_json::json!({"hello": "world"}));
}

#[tokio::test]
async fn test_urlencoded_request_body() {
    async fn handle<B>(request: Request<B>) -> Result<Response<hyper::Body>, anyhow::Error>
    where
        B: http_body::Body + Send,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        if request
            .headers()
            .typed_get::<ContentType>()
            .context("Missing Content-Type header")?
            != ContentType::form_url_encoded()
        {
            bail!("Content-Type header is not application/x-form-urlencoded")
        }

        let bytes = hyper::body::to_bytes(request.into_body()).await?;
        assert_eq!(bytes.to_vec(), br"hello=world".to_vec());

        let res = Response::new(hyper::Body::empty());
        Ok(res)
    }

    let layer = (
        FormUrlencodedRequestLayer::default(),
        BytesToBodyRequestLayer,
    );
    let svc = layer.layer(service_fn(handle));

    let request = Request::new(serde_json::json!({"hello": "world"}));

    let res = svc.oneshot(request).await;
    res.expect("the request to succeed");
}
