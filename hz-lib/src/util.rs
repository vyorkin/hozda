use serde::{Deserialize, Serialize};

use crate::{sha256::Hash, types::Transaction};

#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MerkleRoot(Hash);

impl MerkleRoot {
    pub fn calculate(transactions: &[Transaction]) -> MerkleRoot {
        let mut layer: Vec<Hash> = vec![];

        for tx in transactions {
            let tx_hash = Hash::new(tx);
            layer.push(tx_hash);
        }

        while layer.len() > 1 {
            let mut new_layer = vec![];
            for pair in layer.chunks(2) {
                let left = pair[0];
                let right = pair.get(1).unwrap_or(&pair[0]);
                let pair_hash = Hash::new(&[left, *right]);
                new_layer.push(pair_hash);
            }
            layer = new_layer;
        }

        MerkleRoot(layer[0])
    }
}
