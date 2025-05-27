use crate::{
    HALVING_INTERVAL, INITIAL_REWARD, U256,
    crypto::{PublicKey, Signature},
    error::{self, HzError},
    sha256::Hash,
    util::MerkleRoot,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Blockchain {
    pub utxos: HashMap<Hash, TransactionOutput>,
    pub blocks: Vec<Block>,
}

impl Blockchain {
    pub fn new() -> Self {
        Blockchain {
            utxos: HashMap::new(),
            blocks: vec![],
        }
    }

    pub fn add_block(&mut self, block: Block) -> error::Result<()> {
        if self.blocks.is_empty() {
            // if this is the first block,
            // check if the block's prev_block_hash is all zeroes
            if block.header.prev_block_hash != Hash::zero() {
                println!("zero hash");
                return Err(HzError::InvalidBlock);
            }
        } else {
            // if this is not the first block, check if the
            // block's prev_block_hash is the hash of the last block
            let last_block = self.blocks.last().unwrap();
            if block.header.prev_block_hash != last_block.hash() {
                println!("prev hash is wrong");
                return Err(HzError::InvalidBlock);
            }
            // check if the block's hash is less than the target
            if !block.header.hash().matches_target(block.header.target) {
                println!("does not match target");
                return Err(HzError::InvalidBlock);
            }
            // check if the block's merkle root is correct
            let calculated_merkle_root = MerkleRoot::calculate(&block.transactions);
            if calculated_merkle_root != block.header.merkle_root {
                println!("invalid merkle root");
                return Err(HzError::InvalidMerkleRoot);
            }
            // check if the block's timestamp is after the last block's timestamp
            if block.header.timestamp <= last_block.header.timestamp {
                println!("invalid timestamp");
                return Err(HzError::InvalidBlock);
            }
            // block.verify_transactions(self.block_height(), &self.utxos)?;
        }

        self.blocks.push(block);

        Ok(())
    }

    pub fn rebuild_utxos(&mut self) {
        for block in &self.blocks {
            for tx in &block.transactions {
                // remove the prev_transaction_output_hash, since it is spent
                for input in &tx.inputs {
                    self.utxos.remove(&input.prev_transaction_output_hash);
                }
                for output in &tx.outputs {
                    self.utxos.insert(tx.hash(), output.clone());
                }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Self {
            header,
            transactions,
        }
    }

    pub fn hash(&self) -> Hash {
        Hash::new(self)
    }

    pub fn verify_transactions(
        &self,
        predicted_block_height: u64,
        utxos: &HashMap<Hash, TransactionOutput>,
    ) -> error::Result<()> {
        let mut inputs: HashMap<Hash, TransactionOutput> = HashMap::new();

        // reject empty blocks
        if self.transactions.is_empty() {
            return Err(HzError::InvalidTransaction);
        }

        // the first transaction in a block is special:
        // it is called "coinbase transaction" in which new bitcoin is minted
        self.verfiy_coinbase_transaction(predicted_block_height, utxos)?;
        // excluding the "coinbase transaction" which is verified separately
        for tx in self.transactions.iter().skip(1) {
            let mut input_value = 0;
            let mut output_value = 0;

            for input in &tx.inputs {
                let prev_output = utxos
                    .get(&input.prev_transaction_output_hash)
                    .ok_or(HzError::InvalidTransaction)?;
                // prevent same-block double-spending
                if inputs.contains_key(&input.prev_transaction_output_hash) {
                    return Err(HzError::InvalidTransaction);
                }

                if !input
                    .signature
                    .verify(&input.prev_transaction_output_hash, &prev_output.pubkey)
                {
                    return Err(HzError::InvalidSignature);
                }

                input_value += prev_output.value;
                inputs.insert(input.prev_transaction_output_hash, prev_output.clone());
            }
            for output in &tx.outputs {
                output_value += output.value;
            }

            if input_value < output_value {
                return Err(HzError::InvalidTransaction);
            }
        }

        Ok(())
    }

    pub fn verfiy_coinbase_transaction(
        &self,
        predicted_block_height: u64,
        utxos: &HashMap<Hash, TransactionOutput>,
    ) -> error::Result<()> {
        // coinbase tx is the first transaction in the block
        let coinbase_tx = &self.transactions[0];
        if !coinbase_tx.inputs.is_empty() {
            return Err(HzError::InvalidTransaction);
        }
        if coinbase_tx.outputs.is_empty() {
            return Err(HzError::InvalidTransaction);
        }
        let miner_fees = self.calculate_miner_fees(utxos)?;
        let block_reward = INITIAL_REWARD * 10u64.pow(8)
            / 2u64.pow((predicted_block_height / HALVING_INTERVAL) as u32);

        let total_coinbase_outputs: u64 = coinbase_tx.outputs.iter().map(|o| o.value).sum();
        if total_coinbase_outputs != block_reward + miner_fees {
            return Err(HzError::InvalidTransaction);
        }

        todo!()
    }

    fn calculate_miner_fees(&self, utxos: &HashMap<Hash, TransactionOutput>) -> error::Result<u64> {
        let mut inputs: HashMap<Hash, TransactionOutput> = HashMap::new();
        let mut outputs: HashMap<Hash, TransactionOutput> = HashMap::new();

        // check every transaction after coinbase transaction
        for tx in self.transactions.iter().skip(1) {
            for input in &tx.inputs {
                let prev_output = utxos
                    .get(&input.prev_transaction_output_hash)
                    .ok_or(HzError::InvalidTransaction)?;

                if inputs.contains_key(&input.prev_transaction_output_hash) {
                    return Err(HzError::InvalidTransaction);
                }
                inputs.insert(input.prev_transaction_output_hash, prev_output.clone());
            }
        }

        Ok(0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub timestamp: DateTime<Utc>,
    pub nonce: u64,
    pub prev_block_hash: Hash,
    pub merkle_root: MerkleRoot,
    pub target: U256,
}

impl BlockHeader {
    pub fn new(
        timestamp: DateTime<Utc>,
        nonce: u64,
        prev_block_hash: Hash,
        merkle_root: MerkleRoot,
        target: U256,
    ) -> Self {
        Self {
            timestamp,
            nonce,
            prev_block_hash,
            merkle_root,
            target,
        }
    }

    pub fn hash(&self) -> Hash {
        Hash::new(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
}

impl Transaction {
    pub fn new(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) -> Self {
        Self { inputs, outputs }
    }

    pub fn hash(&self) -> Hash {
        Hash::new(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionInput {
    pub prev_transaction_output_hash: Hash,
    pub signature: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionOutput {
    pub value: u64,
    pub unique_id: Uuid,
    pub pubkey: PublicKey,
}

impl TransactionOutput {
    pub fn hash(&self) -> Hash {
        Hash::new(self)
    }
}
