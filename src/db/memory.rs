use super::Storage;
use crate::{error::MerkleError, node::Node};
use bloock_poseidon_rs::hash::PoseidonHash;
use std::collections::HashMap;

// Implement the trait for an in-memory storage backend
#[derive(Default)]
pub struct MemoryStorage {
    prefix: Vec<u8>,
    kv: HashMap<Vec<u8>, Node>,
    current_root: Option<PoseidonHash>,
}

#[async_trait::async_trait]
impl Storage for MemoryStorage {
    async fn get(&self, key: &PoseidonHash) -> Result<Node, MerkleError> {
        match self.kv.get(&concat(&self.prefix, &key.bytes_be())).cloned() {
            Some(v) => Ok(v),
            None => Err(MerkleError::KeyNotFound),
        }
    }

    async fn put(&mut self, key: &PoseidonHash, node: &Node) -> Result<(), MerkleError> {
        self.kv
            .insert(concat(&self.prefix, &key.bytes_be()), node.clone());
        Ok(())
    }

    async fn get_root(&self) -> Result<Option<PoseidonHash>, MerkleError> {
        Ok(self.current_root)
    }

    async fn set_root(&mut self, hash: &PoseidonHash) -> Result<(), MerkleError> {
        self.current_root = Some(*hash);
        Ok(())
    }
}

fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    [a, b].concat()
}
