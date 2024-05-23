use std::{error::Error, fmt::Display};

use http::Response;
use mas_axum_utils::axum::body::Bytes;
use serde::Deserialize;
use tracing::debug;

/// Represents a Matrix error
/// Ref: <https://spec.matrix.org/v1.10/client-server-api/#standard-error-response>
#[derive(Debug, Deserialize)]
struct MatrixError {
    errcode: String,
    error: String,
}

/// Represents an error received from the homeserver.
/// Where possible, we capture the Matrix error from the JSON response body.
///
/// Note that the `CatchHttpCodes` layer already captures the `StatusCode` for
/// us; we don't need to do that twice.
#[derive(Debug)]
pub(crate) struct HomeserverError {
    matrix_error: Option<MatrixError>,
}

impl Display for HomeserverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(matrix_error) = &self.matrix_error {
            write!(f, "{matrix_error}")
        } else {
            write!(f, "(no specific error)")
        }
    }
}

impl Error for HomeserverError {}

impl HomeserverError {
    /// Return the error code (`errcode`)
    pub fn errcode(&self) -> Option<&str> {
        self.matrix_error.as_ref().map(|me| me.errcode.as_str())
    }
}

/// Parses a JSON-encoded Matrix error from the response body
/// Spec reference: <https://spec.matrix.org/v1.10/client-server-api/#standard-error-response>
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn catch_homeserver_error(response: Response<Bytes>) -> HomeserverError {
    let matrix_error: Option<MatrixError> = match serde_json::from_slice(response.body().as_ref()) {
        Ok(body) => Some(body),
        Err(err) => {
            debug!("failed to deserialise expected homeserver error: {err:?}");
            None
        }
    };
    HomeserverError { matrix_error }
}

impl Display for MatrixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let MatrixError { errcode, error } = &self;
        write!(f, "{errcode}: {error}")
    }
}
