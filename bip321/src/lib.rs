//! BIP 321 payment URI parser and serializer.
//!
//! Implements the `bitcoin:` URI scheme defined in
//! [BIP 321](https://bips.dev/321/) for encoding payment instructions in
//! clickable links and QR codes.
//!
//! # URI format
//!
//! ```text
//! bitcoin:<address>?amount=<btc>&label=<text>&message=<text>
//! ```
//!
//! The on-chain address is optional when at least one alternative payment
//! instruction is present in query parameters (e.g. `lightning=`, `lno=`,
//! `sp=`).
//!
//! # Standard payment instructions
//!
//! The following query parameters are defined in BIP 321 and handled
//! natively: `lightning` (BOLT 11), `lno` (BOLT 12), `sp` (BIP 352
//! Silent Payments), `pay` (BIP 351), and `bc`/`tb` (segwit address
//! HRPs). All of these may appear multiple times.
//!
//! # Required parameters
//!
//! Parameters prefixed with `req-` signal that a wallet **must** understand
//! them to process the URI. Unknown `req-` parameters cause parsing to fail
//! unless an [`ExtensionHandler`] claims support for them.
//!
//! # Extension mechanism
//!
//! Implement [`ExtensionHandler`] to teach the parser about parameters
//! beyond the BIP 321 standard set (e.g. `pj=` for Payjoin, or
//! wallet-specific custom params).
