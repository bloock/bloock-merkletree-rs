use thiserror::Error;

#[derive(Error, Debug)]
pub enum MerkleError {
    #[error("key already exists")]
    NodeKeyAlreadyExists,
    #[error("Key not found in the MerkleTree")]
    KeyNotFound,
    #[error("node data has incorrect size in the DB")]
    NodeBytesBadSize,
    #[error("reached maximum level of the merkle tree")]
    ReachedMaxLevel,
    #[error("found an invalid node in the DB")]
    InvalidNodeFound,
    #[error("found an invalid entry provided")]
    InvalidEntryProvided,
    #[error("the serialized proof is invalid")]
    InvalidProofBytes,
    #[error("the value in the DB is invalid")]
    InvalidDBValue,
    #[error("the entry index already exists in the tree")]
    EntryIndexAlreadyExists,
    #[error("entry not found")]
    EntryNotFound,
    #[error("child not found")]
    ChildNotFound,
    #[error("Merkle Tree not writable")]
    NotWritable,
    #[error("invalid hash: {0}")]
    InvalidHash(String),
    #[error("invalid node: {0}")]
    InvalidNode(String),
    #[error("invalid hash input")]
    InvalidHashInput,
    #[error("error while generating hash: {0}")]
    Hash(String),
    #[error("{0}")]
    Custom(String),
    #[error("unknown data store error")]
    Unknown,
}
