fn main() {
	// Generate the OpenAPI specification
	let openapi = bark_rest::api_doc();

	// Convert to pretty-printed JSON
	let json = serde_json::to_string_pretty(&openapi)
		.expect("Failed to serialize OpenAPI spec to JSON");

	// Print to stdout
	println!("{}", json);
}
