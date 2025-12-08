
use std::fmt;

use anyhow::Context;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// a NOT_FOUND anyhow context object
#[derive(Debug)]
struct NotFound {
	resources: Vec<String>,
	message: String,
}

impl fmt::Display for NotFound {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		if self.resources.is_empty() {
			write!(f, "not found: {}", self.message)?;
		} else {
			f.write_str("not found [resources=")?;
			let mut iter = self.resources.iter().peekable();
			while let Some(r) = iter.next() {
				if iter.peek().is_some() {
					write!(f, "{},", r)?;
				} else {
					write!(f, "{}", r)?;
				}
			}
			write!(f, "]: {}", self.message)?;
		}
		Ok(())
	}
}

impl NotFound {
	fn new<I: fmt::Display>(
		resources: impl IntoIterator<Item = I>,
		message: impl fmt::Display,
	) -> Self {
		NotFound {
			resources: resources.into_iter().map(|r| r.to_string()).collect(),
			message: message.to_string(),
		}
	}
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NotFoundError {
	pub resources: Vec<String>,
	pub message: String,
}

#[allow(unused)]
macro_rules! not_found {
	($ids:expr, $($arg:tt)*) => {
		return Err($crate::error::ErrorResponse::NotFound($crate::error::NotFoundError {
			resources: ($ids).into_iter().map(|r| r.to_string()).collect(),
			message: format!($($arg)*),
		}))
	};
}
pub(crate) use not_found;


/// a BAD_REQUEST anyhow context object
#[derive(Debug)]
struct BadRequest {
	message: String,
}

impl fmt::Display for BadRequest {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "bad request: {}", self.message)
	}
}

impl BadRequest {
	pub fn new(message: impl fmt::Display) -> Self {
		BadRequest {
			message: message.to_string(),
		}
	}
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BadRequestError {
	pub message: String,
}

macro_rules! badarg {
	($($arg:tt)*) => {
		return Err($crate::error::ErrorResponse::BadRequest($crate::error::BadRequestError {
			message: format!($($arg)*),
		}))
	};
}
pub(crate) use badarg;


#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InternalServerError {
	pub message: String,
}

// NB since we don't do any tagging, this is not deserializable
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(untagged)]
pub enum ErrorResponse {
	BadRequest(BadRequestError),
	NotFound(NotFoundError),
	Internal(InternalServerError),
}

impl ErrorResponse {
	pub fn status_code(&self) -> StatusCode {
		match self {
			Self::BadRequest(_) => StatusCode::BAD_REQUEST,
			Self::NotFound(_) => StatusCode::NOT_FOUND,
			Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
		}
	}
}

impl From<anyhow::Error> for ErrorResponse {
	fn from(error: anyhow::Error) -> Self {
		if let Some(c) = error.downcast_ref::<NotFound>() {
			Self::NotFound(NotFoundError {
				resources: c.resources.clone(),
				message: format!("{:#}", error),
			})
		} else if error.is::<BadRequest>() {
			Self::BadRequest(BadRequestError {
				message: format!("{:#}", error),
			})
		} else {
			Self::Internal(InternalServerError {
				message: format!("{:#}", error),
			})
		}
	}
}

impl IntoResponse for ErrorResponse {
	fn into_response(self) -> axum::response::Response {
		(self.status_code(), Json(self)).into_response()
	}
}

/// Extension trait for adding bark-server-specific error info.
pub trait ContextExt<T, E>: Context<T, E> {
	fn badarg<C>(self, context: C) -> anyhow::Result<T>
		where C: fmt::Display + Send + Sync + 'static;

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
		self.context(BadRequest::new(context))
	}

	fn not_found<I, V, C>(self, ids: V, context: C) -> anyhow::Result<T>
	where
		V: IntoIterator<Item = I>,
		I: fmt::Display,
		C: fmt::Display + Send + Sync + 'static,
	{
		self.context(NotFound::new(ids, context))
	}
}

// 404 handler for unmatched routes
pub async fn route_not_found(path: String) -> (StatusCode, Json<String>) {
	(StatusCode::NOT_FOUND, Json(format!("path not round: {}", path)))
}

// Convenience type alias for handlers that return anyhow::Result
pub type HandlerResult<T> = Result<T, ErrorResponse>;
