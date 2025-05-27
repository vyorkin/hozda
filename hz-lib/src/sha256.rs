use core::fmt;

use crate::U256;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub struct Hash(U256);

impl Hash {
    /// Constructs a hash from anything that can be serialized.
    pub fn new<T: Serialize>(data: &T) -> Self {
        let mut serialized: Vec<u8> = vec![];
        if let Err(e) = ciborium::into_writer(data, &mut serialized) {
            panic!("Failed to serialize data: {:?}", e);
        }
        let hash = sha256::digest(&serialized);
        let number = U256::from_str_radix(&hash, 16).unwrap();
        Hash(number)
    }

    /// For a hash to be valid for a mined block,
    /// it has to be a smaller number than the "target".
    /// Target is a number set by network difficulty.
    pub fn matches_target(&self, target: U256) -> bool {
        self.0 <= target
    }

    pub fn zero() -> Self {
        Hash(U256::zero())
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        let bytes = self.0.to_little_endian();
        bytes.as_slice().try_into().unwrap()
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}
