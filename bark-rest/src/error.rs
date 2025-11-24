use std::fmt::{self, Display};

use anyhow::Context;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NotFoundError {
	resource: Vec<String>,
	message: String,
}

impl fmt::Display for NotFoundError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "not found: {}", self.message)
	}
}

impl NotFoundError {
	pub fn new<V, I>(ressource: V, message: impl Display) -> Self
	where V: IntoIterator<Item = I>, I: Display {
		NotFoundError {
			resource: ressource.into_iter().map(|r| r.to_string()).collect::<Vec<_>>(),
			message: message.to_string(),
		}
	}
}

#[allow(unused)]
macro_rules! not_found {
	($ids:expr, $($arg:tt)*) => { return Err($crate::error::ErrorResponse::new_not_found($ids, format!($($arg)*))) };
}
pub(crate) use not_found;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BadRequestError { message: String }

impl fmt::Display for BadRequestError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "bad request: {}", self.message)
	}
}

impl BadRequestError {
	pub fn new(message: impl Display) -> Self {
		BadRequestError { message: message.to_string() }
	}
}

macro_rules! badarg {
	($($arg:tt)*) => { return Err($crate::error::ErrorResponse::new_bad_request(format!($($arg)*))) };
}
pub(crate) use badarg;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InternalServerError { message: String }

impl From<anyhow::Error> for InternalServerError {
	fn from(err: anyhow::Error) -> Self {
		InternalServerError { message: err.to_string() }
	}
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum ErrorResponse {
	NotFound(NotFoundError),
	BadRequest(BadRequestError),
	InternalServerError(InternalServerError),
}

impl ErrorResponse {
	pub fn new_not_found<V, I>(ids: V, message: impl Display) -> Self
	where V: IntoIterator<Item = I>, I: Display {
		ErrorResponse::NotFound(NotFoundError::new(ids, message))
	}

	pub fn new_bad_request(message: impl Display) -> Self {
		ErrorResponse::BadRequest(BadRequestError::new(message))
	}

	fn to_status(&self) -> StatusCode {
		match self {
			ErrorResponse::NotFound(_) => StatusCode::NOT_FOUND,
			ErrorResponse::BadRequest(_) => StatusCode::BAD_REQUEST,
			ErrorResponse::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
		}
	}

	fn to_json(&self) -> Json<serde_json::Value> {
		let value = match self {
			ErrorResponse::NotFound(err) => serde_json::to_value(err).unwrap(),
			ErrorResponse::BadRequest(err) => serde_json::to_value(err).unwrap(),
			ErrorResponse::InternalServerError(err) => serde_json::to_value(err).unwrap(),
		};
		Json(value)
	}
}

impl From<NotFoundError> for ErrorResponse {
	fn from(err: NotFoundError) -> Self {
		ErrorResponse::NotFound(err)
	}
}

impl From<BadRequestError> for ErrorResponse {
	fn from(err: BadRequestError) -> Self {
		ErrorResponse::BadRequest(err)
	}
}

impl From<InternalServerError> for ErrorResponse {
	fn from(err: InternalServerError) -> Self {
		ErrorResponse::InternalServerError(err)
	}
}

impl From<anyhow::Error> for ErrorResponse {
	fn from(err: anyhow::Error) -> Self {
		if let Some(nf) = err.downcast_ref::<NotFoundError>() {
			ErrorResponse::NotFound(nf.clone())
		} else if let Some(ba) = err.downcast_ref::<BadRequestError>() {
			ErrorResponse::BadRequest(ba.clone())
		} else {
			ErrorResponse::InternalServerError(err.into())
		}
	}
}

/// Extension trait for adding bark-server-specific error info.
pub trait ContextExt<T, E>: Context<T, E> {
	/// Turn an anyhow error into an ErrorResponse.
	fn badarg<C>(self, context: C) -> anyhow::Result<T>
		where C: fmt::Display + Send + Sync + 'static;

	/// Turn an anyhow error into an ErrorResponse.
	fn not_found<I, V, C>(self, ids: V, context: C) -> anyhow::Result<T>
	where
		V: IntoIterator<Item = I>,
		I: fmt::Display,
		C: fmt::Display + Send + Sync + 'static;
}


impl<R, T, E> ContextExt<T, E> for R
where
	R: Context<T, E>,
{
	fn badarg<C>(self, context: C) -> anyhow::Result<T>
	where
		C: fmt::Display + Send + Sync + 'static,
	{
		self.context(BadRequestError::new(context))
	}

	fn not_found<I, V, C>(self, ids: V, context: C) -> anyhow::Result<T>
	where
		V: IntoIterator<Item = I>,
		I: fmt::Display,
		C: fmt::Display + Send + Sync + 'static,
	{
		self.context(NotFoundError::new(ids, context))
	}
}


impl IntoResponse for ErrorResponse {
	fn into_response(self) -> axum::response::Response {
		(self.to_status(), self.to_json()).into_response()
	}
}

// 404 handler for unmatched routes
pub async fn route_not_found(path: String) -> (StatusCode, Json<serde_json::Value>) {
	let error_response = ErrorResponse::NotFound(
		NotFoundError::new(vec![path], "Route not found".to_string())
	);
	(error_response.to_status(), error_response.to_json())
}

// Convenience type alias for handlers that return anyhow::Result
pub type HandlerResult<T> = Result<T, ErrorResponse>;
