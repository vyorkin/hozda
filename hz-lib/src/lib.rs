#![allow(clippy::manual_div_ceil)]

use serde::{Deserialize, Serialize};
use uint::construct_uint;

construct_uint! {
    /// Unsigned 256-bit integer.
    /// Consists of 4x64-bit words.
    #[derive(Serialize, Deserialize)]
    pub struct U256(4);
}

/// Initial miner reward.
pub const INITIAL_REWARD: u64 = 50;

/// Halving interval in blocks.
/// After how many blocks we should halve the block reward.
pub const HALVING_INTERVAL: u64 = 210;

/// Ideal block time in seconds.
pub const IDEAL_BLOCK_TIME: u64 = 10;

/// Requires the first 4 hex digits to be zero.
/// We use little-endian encoding: the least significant 64 bits are the last.
pub const MIN_TARGET: U256 = U256([
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x0000_ffff_ffff_ffff,
]);

/// Difficulty update interval in blocks.
/// In real bitcoin it is set to 2016.
pub const DIFFICULTY_UPDATE_INTERVAL: u64 = 50;

pub mod crypto;
pub mod error;
pub mod sha256;
pub mod types;
pub mod util;
