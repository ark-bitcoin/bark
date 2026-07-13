# Cairo ABI source fixture

`ark_taproot_miniscript_claim_v1.cairo` is an exact LF-normalized copy of the
Ark VTXO Prover source supplied with this interoperability work. The source
project's README declares the project to be MIT licensed. No canonical public
repository or commit was available when the fixture was copied, so this file
is the self-contained compatibility artifact.

The fixture's SHA-256 is
`ab422d117be16af2a2754a838769b4fa19b97f694af88309a82233669f59c472`.

It was compiled with Scarb 2.18.0, Cairo edition `2024_07`, and
`cairo_execute`/`cairo_test` 2.18.0. From the Bark repository root, verify the
pin with `cargo test -p bark-shinigami --test cairo_source` and compile and run
all checked-in vectors with `sh shinigami/tests/execute-cairo-vectors.sh`.
