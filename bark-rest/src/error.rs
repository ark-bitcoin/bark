use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

// Custom error response type
#[derive(serde::Serialize)]
pub struct ErrorResponse {
	error: String,
}

// Custom error type that wraps anyhow::Error
#[derive(Debug)]
pub struct AnyhowError(anyhow::Error);

impl From<anyhow::Error> for AnyhowError {
	fn from(err: anyhow::Error) -> Self {
		AnyhowError(err)
	}
}

impl IntoResponse for AnyhowError {
	fn into_response(self) -> axum::response::Response {
		let error_response = ErrorResponse {
			error: self.0.to_string(),
		};
		(StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
	}
}

// 404 handler for unmatched routes
pub async fn not_found() -> (axum::http::StatusCode, Json<ErrorResponse>) {
	let error_response = ErrorResponse {
		error: "Route not found".to_string(),
	};
	(axum::http::StatusCode::NOT_FOUND, Json(error_response))
}

// Convenience type alias for handlers that return anyhow::Result
pub type HandlerResult<T> = Result<T, AnyhowError>;
