use bitcoin::NetworkKind;

/// Errors returned when parsing or constructing a `bitcoin:` URI.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Bip321Error {
	/// The URI is shorter than the `bitcoin:` scheme prefix.
	#[error("uri is too short")]
	TooShort,

	/// The URI does not start with `bitcoin:` (case-insensitive).
	#[error("invalid scheme")]
	InvalidScheme,

	/// The on-chain address could not be parsed.
	#[error("invalid bitcoin address: {0}")]
	InvalidAddress(String),

	/// The provided payment destination is not valid for the network
	#[error("test address must be valid for the {expected:?} network")]
	NetworkKindMismatch { expected: NetworkKind },

	/// A query parameter value could not be decoded or parsed.
	#[error("malformed parameter: {0}")]
	MalformedParam(String),

	/// Percent-decoding produced invalid UTF-8.
	#[error("UTF-8 decode error: {0}")]
	Utf8Error(#[from] std::str::Utf8Error),

	/// The same non-duplicable parameter appeared more than once.
	#[error("duplicate parameter: {0}")]
	DuplicateParam(String),

	/// No on-chain address and no alternative payment instructions found.
	#[error("no payment destination: address or payment instruction required")]
	NoPaymentDestination,

	/// The `amount` parameter was set to zero.
	#[error("amount must not be zero")]
	AmountZero,

	/// A PoP URI uses a required scheme that is not safe.
	#[error("required scheme in pop URI is not safe: {0}")]
	RequiredUnsafePopScheme(String),

	/// The provided payment destination is not valid for the network
	#[error("payment instruction parse error on key {key}: {error}")]
	PaymentInstructionParseError { key: String, error: String },

	/// An extension handler returned an error.
	#[error("extension error: {0}")]
	ExtensionError(String),

	/// An unknown `req-` parameter was encountered and not handled.
	#[error("unsupported required parameter: {0}")]
	UnsupportedRequiredParam(String),
}
