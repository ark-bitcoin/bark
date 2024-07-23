#!/usr/bin/env sh

RUSTDOCSDIR=${PWD}/rustdocs
mkdir -p ${RUSTDOCSDIR}

cargo doc --target-dir ${RUSTDOCSDIR} --all --lib --examples --document-private-items

# This is opinionated, but doesn't matter. Any page has full search.
DEFAULT_CRATE=bark
echo "Open Rust docs at file://${RUSTDOCSDIR}/doc/${DEFAULT_CRATE}/index.html"
