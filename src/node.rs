use super::error::MerkleError;
use super::utils::hash_elems;
use crate::utils::hash_elems_key;
use bloock_poseidon_rs::hash::PoseidonHash;
use num_bigint::BigUint;
use std::fmt;
use std::vec::Vec;

#[derive(Debug, Clone, PartialEq)]
pub enum NodeType {
    Middle,
    Leaf,
    Empty,
}

#[derive(Debug, Clone)]
pub struct Node {
    node_type: NodeType,
    child_l: Option<PoseidonHash>,
    child_r: Option<PoseidonHash>,
    entry: Option<[PoseidonHash; 2]>,
    key: PoseidonHash,
}

impl Node {
    pub fn new_leaf(k: PoseidonHash, v: PoseidonHash) -> Result<Self, MerkleError> {
        let node_type = NodeType::Leaf;
        let child_l = None;
        let child_r = None;
        let entry = Some([k, v]);
        let key = Node::calculate_key(&node_type, child_l, child_r, entry)?;

        Ok(Node {
            node_type,
            child_l,
            child_r,
            entry,
            key,
        })
    }

    pub fn new_middle(child_l: PoseidonHash, child_r: PoseidonHash) -> Result<Self, MerkleError> {
        let node_type = NodeType::Middle;
        let child_l = Some(child_l);
        let child_r = Some(child_r);
        let entry = None;
        let key = Node::calculate_key(&node_type, child_l, child_r, entry)?;

        Ok(Node {
            node_type,
            child_l,
            child_r,
            entry,
            key,
        })
    }

    pub fn new_empty() -> Result<Self, MerkleError> {
        let node_type = NodeType::Empty;
        let child_l = None;
        let child_r = None;
        let entry = None;
        let key = Node::calculate_key(&node_type, child_l, child_r, entry)?;

        Ok(Node {
            node_type,
            child_l,
            child_r,
            entry,
            key,
        })
    }

    pub fn key(&self) -> PoseidonHash {
        self.key
    }

    fn calculate_key(
        node_type: &NodeType,
        child_l: Option<PoseidonHash>,
        child_r: Option<PoseidonHash>,
        entry: Option<[PoseidonHash; 2]>,
    ) -> Result<PoseidonHash, MerkleError> {
        Ok(match node_type {
            NodeType::Middle => {
                let child_l = child_l.ok_or(MerkleError::InvalidNode(
                    "Middle node missing left child".into(),
                ))?;
                let child_r = child_r.ok_or(MerkleError::InvalidNode(
                    "Middle node missing right child".into(),
                ))?;

                hash_elems(&[child_l.bigint(), child_r.bigint()])?
            }
            NodeType::Leaf => {
                let entry =
                    entry.ok_or(MerkleError::InvalidNode("Leaf node missing entry".into()))?;
                let k = entry[0].bigint();
                let v = entry[1].bigint();

                hash_elems_key(&BigUint::from(1u32), &[&k, &v])?
            }
            NodeType::Empty => PoseidonHash::default(),
        })
    }

    pub fn value(&self) -> Vec<u8> {
        let mut value = vec![self.node_type_byte()];
        match self.node_type {
            NodeType::Middle => {
                if let (Some(child_l), Some(child_r)) = (&self.child_l, &self.child_r) {
                    value.extend_from_slice(&child_l.bytes_be());
                    value.extend_from_slice(&child_r.bytes_be());
                }
            }
            NodeType::Leaf => {
                if let Some(entry) = &self.entry {
                    value.extend_from_slice(&entry[0].bytes_be());
                    value.extend_from_slice(&entry[1].bytes_be());
                }
            }
            NodeType::Empty => {}
        }
        value
    }

    pub fn entry(&self) -> Option<[PoseidonHash; 2]> {
        self.entry
    }

    pub fn node_type(&self) -> NodeType {
        self.node_type.clone()
    }

    pub fn child_l(&self) -> Option<PoseidonHash> {
        self.child_l
    }

    pub fn child_r(&self) -> Option<PoseidonHash> {
        self.child_r
    }

    fn node_type_byte(&self) -> u8 {
        match self.node_type {
            NodeType::Middle => 0,
            NodeType::Leaf => 1,
            NodeType::Empty => 2,
        }
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.node_type {
            NodeType::Middle => {
                let child_l = self.child_l.as_ref().unwrap();
                let child_r = self.child_r.as_ref().unwrap();
                write!(f, "Middle L:{:?} R:{:?}", child_l, child_r)
            }
            NodeType::Leaf => {
                let entry = self.entry.as_ref().unwrap();
                write!(f, "Leaf I:{} D:{}", entry[0].bigint(), entry[1].bigint())
            }
            NodeType::Empty => write!(f, "Empty"),
        }
    }
}
