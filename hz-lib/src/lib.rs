#![allow(clippy::manual_div_ceil)]

use serde::{Deserialize, Serialize};
use uint::construct_uint;

construct_uint! {
    /// Unsigned 256-bit integer.
    /// Consists of 4x64-bit words.
    #[derive(Serialize, Deserialize)]
    pub struct U256(4);
}

pub mod crypto;
pub mod sha256;
pub mod types;
pub mod util;
