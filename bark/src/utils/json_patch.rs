//! RFC 7396 JSON Merge Patch.
//!
//! See <https://www.rfc-editor.org/rfc/rfc7396>.
//!
//! A JSON merge patch describes modifications to a target JSON document
//! using syntax that mimics the document. A `null` value in the patch
//! deletes the corresponding key; any other value replaces or recursively
//! merges. The operation is infallible: every pair of JSON values has a
//! defined result.

use serde_json::{Map, Value};

/// Apply an RFC 7396 JSON Merge Patch to `target` in place.
///
/// The algorithm follows section 2 of the RFC verbatim:
///
/// - If `patch` is not a JSON object, `target` is replaced by `patch`.
/// - Otherwise, for every name/value pair in `patch`:
///   - If the value is `null`, the name is removed from `target` (if present).
///   - Otherwise, the value is recursively merged into `target[name]`,
///     creating `target[name]` first if it doesn't exist.
/// - If `patch` is an object but `target` is not, `target` is first
///   reset to an empty object before the merge proceeds.
///
/// Consequences worth noting (all required by the RFC):
///
/// - Arrays are opaque values and are never merged element-wise.
/// - A merge patch cannot set a key to `null`; `null` always means delete.
/// - A pre-existing `null` in `target` is preserved if the patch does not
///   mention that key.
pub fn merge(target: &mut Value, patch: &Value) {
	let Value::Object(patch_map) = patch else {
		*target = patch.clone();
		return;
	};

	if !target.is_object() {
		*target = Value::Object(Map::new());
	}
	// Safe: just ensured target is an object.
	let target_map = target.as_object_mut().unwrap();

	for (key, value) in patch_map {
		if value.is_null() {
			target_map.remove(key);
		} else {
			let entry = target_map.entry(key.as_str()).or_insert(Value::Null);
			merge(entry, value);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	#[track_caller]
	fn check(original: Value, patch: Value, expected: Value) {
		let mut buf = original.clone();
		merge(&mut buf, &patch);
		assert_eq!(
			buf, expected,
			"\n  original: {original}\n  patch:    {patch}\n  expected: {expected}\n  result:   {buf}",
		);
	}

	// --- RFC 7396 Appendix A: the 15 normative test vectors ---------------

	#[test]
	fn rfc_appendix_a_01_replace_value() {
		check(json!({"a":"b"}), json!({"a":"c"}), json!({"a":"c"}));
	}

	#[test]
	fn rfc_appendix_a_02_add_value() {
		check(json!({"a":"b"}), json!({"b":"c"}), json!({"a":"b","b":"c"}));
	}

	#[test]
	fn rfc_appendix_a_03_null_removes_sole_key() {
		check(json!({"a":"b"}), json!({"a":null}), json!({}));
	}

	#[test]
	fn rfc_appendix_a_04_null_removes_one_of_many() {
		check(
			json!({"a":"b","b":"c"}),
			json!({"a":null}),
			json!({"b":"c"}),
		);
	}

	#[test]
	fn rfc_appendix_a_05_array_replaced_by_string() {
		check(json!({"a":["b"]}), json!({"a":"c"}), json!({"a":"c"}));
	}

	#[test]
	fn rfc_appendix_a_06_string_replaced_by_array() {
		check(json!({"a":"c"}), json!({"a":["b"]}), json!({"a":["b"]}));
	}

	#[test]
	fn rfc_appendix_a_07_nested_merge_with_null_removal() {
		check(
			json!({"a": {"b": "c"}}),
			json!({"a": {"b": "d", "c": null}}),
			json!({"a": {"b": "d"}}),
		);
	}

	#[test]
	fn rfc_appendix_a_08_arrays_are_never_merged() {
		check(
			json!({"a": [{"b":"c"}]}),
			json!({"a": [1]}),
			json!({"a": [1]}),
		);
	}

	#[test]
	fn rfc_appendix_a_09_top_level_array_replaced() {
		check(json!(["a","b"]), json!(["c","d"]), json!(["c","d"]));
	}

	#[test]
	fn rfc_appendix_a_10_object_replaced_by_array() {
		check(json!({"a":"b"}), json!(["c"]), json!(["c"]));
	}

	#[test]
	fn rfc_appendix_a_11_null_patch_replaces_with_null() {
		check(json!({"a":"foo"}), json!(null), json!(null));
	}

	#[test]
	fn rfc_appendix_a_12_string_patch_replaces() {
		check(json!({"a":"foo"}), json!("bar"), json!("bar"));
	}

	#[test]
	fn rfc_appendix_a_13_existing_null_preserved() {
		check(
			json!({"e":null}),
			json!({"a":1}),
			json!({"e":null,"a":1}),
		);
	}

	#[test]
	fn rfc_appendix_a_14_non_object_target_becomes_object() {
		check(
			json!([1,2]),
			json!({"a":"b","c":null}),
			json!({"a":"b"}),
		);
	}

	#[test]
	fn rfc_appendix_a_15_recursive_creation_with_inner_null() {
		check(
			json!({}),
			json!({"a":{"bb":{"ccc":null}}}),
			json!({"a":{"bb":{}}}),
		);
	}

	// --- RFC 7396 section 3 worked example -------------------------------

	#[test]
	fn rfc_section_3_worked_example() {
		let original = json!({
			"title": "Goodbye!",
			"author": {
				"givenName": "John",
				"familyName": "Doe",
			},
			"tags": ["example", "sample"],
			"content": "This will be unchanged",
		});
		let patch = json!({
			"title": "Hello!",
			"phoneNumber": "+01-123-456-7890",
			"author": { "familyName": null },
			"tags": ["example"],
		});
		let expected = json!({
			"title": "Hello!",
			"author": { "givenName": "John" },
			"tags": ["example"],
			"content": "This will be unchanged",
			"phoneNumber": "+01-123-456-7890",
		});
		check(original, patch, expected);
	}
}
