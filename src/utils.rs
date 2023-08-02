use super::error::MerkleError;
use bloock_poseidon_rs::hash::PoseidonHash;
use bloock_poseidon_rs::poseidon::{Fr, Poseidon};
use bloock_poseidon_rs::PrimeField;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::Num;

const Q_STR: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

lazy_static! {
    static ref POSEIDON: Poseidon = Poseidon::default();
    static ref Q: BigUint = BigUint::from_str_radix(Q_STR, 10).expect("Failed to parse Q constant");
}

pub fn hash_elems(elems: &[BigUint]) -> Result<PoseidonHash, MerkleError> {
    let t: Vec<Fr> = elems
        .iter()
        .filter_map(|e| Fr::from_str(&e.to_string()))
        .collect();

    POSEIDON.hash(&t).map_err(MerkleError::Hash)
}

pub fn hash_elems_key(key: &BigUint, elems: &[&BigUint]) -> Result<PoseidonHash, MerkleError> {
    let t: Vec<Fr> = elems
        .iter()
        .filter_map(|e| Fr::from_str(&e.to_string()))
        .collect();
    let mut bi = Vec::with_capacity(3);
    bi.extend_from_slice(&t);
    bi.push(Fr::from_str(&key.to_string()).ok_or(MerkleError::InvalidHashInput)?);

    POSEIDON.hash(&bi).map_err(MerkleError::Hash)
}

pub fn test_bit(bitmap: &[u8], n: usize) -> bool {
    let index = n / 8;
    let offset = (n % 8) as u8;
    let b = bitmap[index] & (1 << offset);
    b != 0
}
