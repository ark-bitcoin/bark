use bark_rest::ApiDoc;
use utoipa::OpenApi;

fn main() {
	// Generate the OpenAPI specification
	let openapi = ApiDoc::openapi();

	// Convert to pretty-printed JSON
	let json = serde_json::to_string_pretty(&openapi)
		.expect("Failed to serialize OpenAPI spec to JSON");

	// Print to stdout
	println!("{}", json);
}
