#[macro_use]
extern crate prost_derive; // i'll use that for now, until prost solve the problem of rust 2018

pub mod devices;
pub mod ecc;
mod error;
pub mod identity_key;
mod protos;
mod utils;
