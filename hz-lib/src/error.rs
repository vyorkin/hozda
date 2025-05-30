use thiserror::Error;

pub type Result<T> = std::result::Result<T, HzError>;

#[derive(Error, Debug)]
pub enum HzError {
    #[error("Invalid transaction")]
    InvalidTransaction,
    #[error("Invalid block")]
    InvalidBlock,
    #[error("Invalid block header")]
    InvalidBlockHeader,
    #[error("Invalid transaction input")]
    InvalidTransactionInput,
    #[error("Invalid transaction output")]
    InvalidTransactionOutput,
    #[error("Invalid merkle root")]
    InvalidMerkleRoot,
    #[error("Invalid hash")]
    InvalidHash,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid private key")]
    InvalidPrivateKey,
}
