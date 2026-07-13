//! Experimental interoperability between Bark VTXOs and external Cairo inputs.
//!
//! This crate only exports deterministic inputs. It does not execute Bitcoin
//! Script, invoke Shinigami, generate a STARK proof, or verify a proof. Nothing
//! returned by this crate is spend authorization or a consensus validation
//! result.

pub mod v1;
