
pub extern crate ark;
pub extern crate bitcoin;
pub extern crate hal;

#[macro_use] extern crate serde;

pub mod cli;
pub mod exit;
pub mod primitives;
pub mod web;
mod serde_utils;

pub use primitives::*;
pub use web::*;


