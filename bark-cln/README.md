# Bark for Core Lightning

This crate contains functonality required for Core Lightning integration.

## gRPC

The crate adds gRPC bindings to Core Lightning.
We could use the [`cln-grpc`](https://crates.io/crates/cln-grpc) crate which bundles
the same gRPC interface and it's own version of tonic. 

However, I prefer to use a single version of `tonic` for the entire project and 
decided to bundle the bindings in a new crate.
