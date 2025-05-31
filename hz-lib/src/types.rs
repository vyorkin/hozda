use crate::{
    DIFFICULTY_UPDATE_INTERVAL, HALVING_INTERVAL, IDEAL_BLOCK_TIME, INITIAL_REWARD, MIN_TARGET,
    U256,
    crypto::{PublicKey, Signature},
    error::{self, HzError},
    sha256::Hash,
    util::MerkleRoot,
};
use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Unspent transaction output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    /// Is marked for spending by a transaction in the mempool.
    pub marked_for_spending: bool,
    pub output: TransactionOutput,
}

impl Utxo {
    pub fn new(output: TransactionOutput) -> Self {
        Self {
            marked_for_spending: false,
            output,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Blockchain {
    utxos: HashMap<Hash, Utxo>,
    target: U256,
    blocks: Vec<Block>,
    #[serde(default, skip_serializing)]
    mempool: Vec<Transaction>,
}

impl Blockchain {
    pub fn new() -> Self {
        Blockchain {
            utxos: HashMap::new(),
            target: MIN_TARGET,
            blocks: vec![],
            mempool: vec![],
        }
    }

    pub fn utxos(&self) -> &HashMap<Hash, Utxo> {
        &self.utxos
    }

    pub fn target(&self) -> U256 {
        self.target
    }

    pub fn blocks(&self) -> impl Iterator<Item = &Block> {
        self.blocks.iter()
    }

    pub fn mempool(&self) -> &[Transaction] {
        &self.mempool
    }

    /// Total number of blocks in blockchain.
    pub fn block_height(&self) -> u64 {
        self.blocks.len() as u64
    }

    // - Track the time when tx was inserted into mempool
    // - Remove tx if it has been in mempool for too long
    //
    // - Mark UTXO's that are referenced by a tx in mempool
    // - Remove old tx that marks those UTXO's.
    //
    // Here is what happens:
    //
    // 1. A new tx enters the mempool,
    //    it wants to spend certain UTXO's (Unspent Transaction Outputs)
    // 2. We mark these UTXO's as `marked_for_spending`
    //    indicating that this tx intends to spend them
    // 3. Conflict detection:
    //    we check if there's already another tx in the
    //    mempool trying to spend the same UTXO's
    // 4. Removing the old tx:
    //    if such tx is found, the old tx gets removed from the mempool and
    //    marked_for_spending is set to false for all UTXO's it references

    pub fn add_tx_to_mempool(&mut self, tx: Transaction) -> error::Result<()> {
        // we must validate transaction before insertion:
        //
        // 1. sum of output amounts should be less or equal to sum of input amounts
        //    (the difference between the two is the miner fee)
        // 2. all inputs must have a known/matching UTXO
        // 3. all inputs must be unique
        //    (no double-spending with a single transaction)

        let mut known_input_hashes = HashSet::new();

        // all inputs must match known UTXO's, and must be unique
        for input in &tx.inputs {
            if !self.utxos.contains_key(&input.prev_tx_output_hash) {
                return Err(HzError::InvalidTransaction);
            }
            if known_input_hashes.contains(&input.prev_tx_output_hash) {
                return Err(HzError::InvalidTransaction);
            }
            known_input_hashes.insert(input.prev_tx_output_hash);
        }

        for input in &tx.inputs {
            // if there exists another tx in the mempool trying to spend the same UTXO
            if let Some(Utxo {
                marked_for_spending: true,
                ..
            }) = self.utxos.get(&input.prev_tx_output_hash)
            {
                // find the transaction that already references (spends) the UTXO
                let existing_tx = self.mempool.iter().enumerate().find(|(_, tx)| {
                    tx.outputs
                        .iter()
                        .any(|output| output.hash() == input.prev_tx_output_hash)
                });

                // if we found it, set marked_for_spending = false
                // for all UTXO's it references
                if let Some((idx, existing_tx)) = existing_tx {
                    for input in &existing_tx.inputs {
                        // OK, THATS ENOUGH.
                        // I must say I'm disappointed with this book.
                        // The absence of tests makes it difficult to validate the functionality.
                        // I'm discontinuing this study as it appears to be an inefficient allocation of my time.
                        // IN OTHER WORDS:
                        // Fuck it.
                    }
                }
            }
        }

        // all inputs must be lower than all outputs
        let all_inputs = tx
            .inputs
            .iter()
            .map(|input| {
                self.utxos
                    .get(&input.prev_tx_output_hash)
                    .expect("No matching UTXO for tx input")
                    .output
                    .value
            })
            .sum::<u64>();
        let all_outputs = tx.outputs.iter().map(|output| output.value).sum::<u64>();

        if all_inputs < all_outputs {
            return Err(HzError::InvalidTransaction);
        }

        self.mempool.push(tx);

        // miners are incentivized to assemble blocks from transactions that
        // have the highest fees first, so we want pre-sort tx's by fee size
        self.mempool.sort_by_key(|tx| {
            let all_inputs = tx
                .inputs
                .iter()
                .map(|input| {
                    self.utxos
                        .get(&input.prev_tx_output_hash)
                        .expect("No matching UTXO for tx input")
                        .output
                        .value
                })
                .sum::<u64>();
            let all_outputs = tx.outputs.iter().map(|output| output.value).sum::<u64>();
            all_inputs - all_outputs
        });

        Ok(())
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
            block.verify_transactions(self.block_height(), &self.utxos)?;
        }

        // remove block transactions from the mempool
        let block_transaction_hashes: HashSet<_> =
            block.transactions.iter().map(|tx| tx.hash()).collect();

        self.mempool
            .retain(|tx| !block_transaction_hashes.contains(&tx.hash()));
        self.blocks.push(block);
        self.try_adjust_target();

        Ok(())
    }

    fn try_adjust_target(&mut self) {
        if self.blocks.is_empty() {
            return;
        }
        // not enough blocks yet
        if self.blocks.len() % DIFFICULTY_UPDATE_INTERVAL as usize != 0 {
            return;
        }

        // measure the time it took to mine the last DIFFICULTY_UPDATE_INTERVAL blocks
        let start_time = self.blocks[self.blocks.len() - DIFFICULTY_UPDATE_INTERVAL as usize]
            .header
            .timestamp;

        let end_time = self.blocks.last().unwrap().header.timestamp;
        let time_diff = end_time - start_time;
        let actual_time_diff_seconds = time_diff.num_seconds();

        // calculate the ideal number of seconds
        let ideal_time_diff_seconds = IDEAL_BLOCK_TIME * DIFFICULTY_UPDATE_INTERVAL;

        let current_target = BigDecimal::parse_bytes(self.target.to_string().as_bytes(), 10)
            .expect("Can't parse target: U256 as BigDecimal");

        // new_target = current_target * (actual_time / ideal_time)
        let new_target = current_target
            * (BigDecimal::from(actual_time_diff_seconds)
                / BigDecimal::from(ideal_time_diff_seconds));

        // since U256 and BigDecimal don't know about each other
        // we need to go through the string representation

        // U256 expects that there will be no decimal point in
        // the string representation, so we need to cut it off
        let new_target_str = new_target
            .to_string()
            .split('.')
            .next()
            .expect("Expected a decimal point")
            .to_owned();

        let new_target: U256 = U256::from_str_radix(&new_target_str, 10)
            .expect("Can't parse new_target_str (BigDecimal) as U256");

        // clamp new_target to be within [target / 4, target * 4]
        // so that we do not increase or decrease the target by more than a factor of 4x
        let new_target = if new_target < self.target / 4 {
            self.target / 4
        } else if new_target > self.target * 4 {
            self.target * 4
        } else {
            new_target
        };
        // ensure we do not decrease the target below minimum target
        self.target = new_target.min(MIN_TARGET);
    }

    pub fn rebuild_utxos(&mut self) {
        for block in &self.blocks {
            for tx in &block.transactions {
                // remove the prev_transaction_output_hash, since it is spent
                for input in &tx.inputs {
                    self.utxos.remove(&input.prev_tx_output_hash);
                }
                for output in &tx.outputs {
                    let tx_output_hash = tx.hash();
                    let utxo = Utxo::new(output.clone());
                    self.utxos.insert(tx_output_hash, utxo);
                }
            }
        }
    }
}

impl Default for Blockchain {
    fn default() -> Self {
        Self::new()
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
        utxos: &HashMap<Hash, Utxo>,
    ) -> error::Result<()> {
        let mut inputs: HashMap<Hash, TransactionOutput> = HashMap::new();

        // reject empty blocks
        if self.transactions.is_empty() {
            return Err(HzError::InvalidTransaction);
        }

        // the first transaction in a block is special:
        // it is called "coinbase transaction" in which new bitcoin is minted
        self.verify_coinbase_transaction(predicted_block_height, utxos)?;
        // excluding the "coinbase transaction" which is verified separately
        for tx in self.transactions.iter().skip(1) {
            let mut input_value = 0;
            let mut output_value = 0;

            for input in &tx.inputs {
                let utxo = utxos
                    .get(&input.prev_tx_output_hash)
                    .ok_or(HzError::InvalidTransaction)?;

                // prevent same-block double-spending
                if inputs.contains_key(&input.prev_tx_output_hash) {
                    return Err(HzError::InvalidTransaction);
                }

                if !input
                    .signature
                    .verify(&input.prev_tx_output_hash, &utxo.output.pubkey)
                {
                    return Err(HzError::InvalidSignature);
                }

                input_value += utxo.output.value;
                inputs.insert(input.prev_tx_output_hash, utxo.output.clone());
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

    pub fn verify_coinbase_transaction(
        &self,
        predicted_block_height: u64,
        utxos: &HashMap<Hash, Utxo>,
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

    /// miner_fees = sum(tx.inputs) - sum(tx.outputs)
    fn calculate_miner_fees(&self, utxos: &HashMap<Hash, Utxo>) -> error::Result<u64> {
        let mut inputs: HashMap<Hash, TransactionOutput> = HashMap::new();
        let mut outputs: HashMap<Hash, TransactionOutput> = HashMap::new();

        // check every transaction after coinbase transaction
        for tx in self.transactions.iter().skip(1) {
            for input in &tx.inputs {
                // inputs do not contain the values of the outputs,
                // so we need to match inputs to outputs

                let utxo = utxos
                    .get(&input.prev_tx_output_hash)
                    .ok_or(HzError::InvalidTransaction)?;

                // same-block double-spending check (again)
                if inputs.contains_key(&input.prev_tx_output_hash) {
                    return Err(HzError::InvalidTransaction);
                }

                inputs.insert(input.prev_tx_output_hash, utxo.output.clone());
            }

            // check for duplicate outputs
            for output in &tx.outputs {
                if outputs.contains_key(&output.hash()) {
                    return Err(HzError::InvalidTransaction);
                }
                outputs.insert(output.hash(), output.clone());
            }
        }

        let input_value: u64 = inputs.values().map(|input| input.value).sum();
        let output_value: u64 = outputs.values().map(|output| output.value).sum();

        Ok(input_value - output_value)
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

    /// Rotates the nonce and if runs out of the nonce, updates the timestamp.
    /// We only do a finite number of steps at a time because we may want to
    /// interrupt the mining if we receive an update from the network that
    /// we should work a new block (bacause the new block has been found in the meantime).
    pub fn mine(&mut self, steps: usize) -> bool {
        // The PoW involves scanning for a value that when hashed with SHA-256,
        // the hash begins with a number of 0-bits.
        // The avg. work is exponential in the number of 0-bits required.

        // Here we implement PoW by incrementing a nonce in the block until
        // a value is found that gives the block's hash the required number of 0-bits.

        if self.hash().matches_target(self.target) {
            return true;
        }
        for _ in 0..steps {
            if let Some(new_nonce) = self.nonce.checked_add(1) {
                self.nonce = new_nonce;
            } else {
                self.nonce = 0;
                self.timestamp = Utc::now();
            }

            if self.hash().matches_target(self.target) {
                return true;
            }
        }
        false
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
    /// The hash of the previous transaction output,
    /// which is linked into this transaction input.
    pub prev_tx_output_hash: Hash,
    pub signature: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionOutput {
    pub unique_id: Uuid,
    pub value: u64,
    pub pubkey: PublicKey,
}

impl TransactionOutput {
    pub fn hash(&self) -> Hash {
        Hash::new(self)
    }
}
