// TODO: remove before 1.0.0
#![allow(dead_code)]

#[macro_use]
#[cfg(feature = "cesr")]
pub mod cesr;
#[macro_use]
#[cfg(feature = "signify")]
pub mod signing;
#[cfg(feature = "signify")]
pub mod signify;
#[macro_use]
#[cfg(feature = "prefixing")]
pub mod prefexing;
#[macro_use]
#[cfg(feature = "pathing")]
pub mod pathing;

pub mod crypto;
pub mod data;
pub mod error;
pub mod messaging;
pub mod receipting;
pub mod seal;
