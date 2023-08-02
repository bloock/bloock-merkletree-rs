use super::{error::MerkleError, node::Node};
use async_trait::async_trait;
use bloock_poseidon_rs::hash::PoseidonHash;

pub mod memory;

#[async_trait]
pub trait Storage {
    async fn get(&self, k: &PoseidonHash) -> Result<Node, MerkleError>;
    async fn put(&mut self, k: &PoseidonHash, v: &Node) -> Result<(), MerkleError>;
    async fn get_root(&self) -> Result<Option<PoseidonHash>, MerkleError>;
    async fn set_root(&mut self, root: &PoseidonHash) -> Result<(), MerkleError>;
}
