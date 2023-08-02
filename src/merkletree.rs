use super::db::Storage;
use super::error::MerkleError;
use super::node::{Node, NodeType};
use super::utils::test_bit;
use async_recursion::async_recursion;
use bloock_poseidon_rs::hash::PoseidonHash;
use num_bigint::BigUint;
use std::cell::RefCell;

// IndexLen indicates how many elements are used for the index.
pub const INDEX_LEN: usize = 4;

// DataLen indicates how many elements are used for the data.
pub const DATA_LEN: usize = 8;

pub const ELEM_BYTES_LEN: usize = 32;

pub struct MerkleTree<S: Storage> {
    db: S,
    root_key: PoseidonHash,
    writable: bool,
    max_levels: usize,
}

impl<S: Storage> MerkleTree<S> {
    pub async fn new(storage: S, max_levels: usize) -> Result<Self, MerkleError> {
        let mut mt = MerkleTree {
            db: storage,
            max_levels,
            writable: true,
            root_key: PoseidonHash::default(), // Assuming Hash implements Default
        };

        let root_opt = mt.db.get_root().await?;

        if let Some(root) = root_opt {
            mt.root_key = root;
            Ok(mt)
        } else {
            mt.db.set_root(&mt.root_key).await?;
            Ok(mt)
        }
    }

    pub fn root(&self) -> &PoseidonHash {
        &self.root_key
    }

    // MaxLevels returns the MT maximum level
    pub fn max_levels(&self) -> usize {
        self.max_levels
    }

    // Add adds a Key & Value into the MerkleTree. Where the `k` determines the
    // path from the Root to the Leaf.
    pub async fn add(&mut self, k: &BigUint, v: &BigUint) -> Result<(), MerkleError> {
        // verify that the MerkleTree is writable
        if !self.writable {
            return Err(MerkleError::NotWritable);
        }

        let k_hash = PoseidonHash::from(k);
        let v_hash = PoseidonHash::from(v);

        let new_node_leaf = Node::new_leaf(k_hash, v_hash)?;
        let path = self.get_path(self.max_levels, &k_hash);

        let root = *self.root();
        let new_root_key = self.add_leaf(&new_node_leaf, &root, 0, &path).await?;
        self.root_key = new_root_key;
        self.db.set_root(&self.root_key).await?;

        Ok(())
    }

    fn get_path(&self, num_levels: usize, k: &PoseidonHash) -> Vec<bool> {
        let mut path = Vec::with_capacity(num_levels);
        for n in 0..num_levels {
            path.push(test_bit(&k.bytes_le(), n));
        }
        path
    }

    #[async_recursion(?Send)]
    async fn push_leaf(
        &mut self,
        new_leaf: &Node,
        old_leaf: &Node,
        lvl: usize,
        path_new_leaf: &[bool],
        path_old_leaf: &[bool],
    ) -> Result<PoseidonHash, MerkleError> {
        if lvl > self.max_levels - 2 {
            return Err(MerkleError::ReachedMaxLevel);
        }

        if path_new_leaf[lvl] == path_old_leaf[lvl] {
            let next_key = self
                .push_leaf(new_leaf, old_leaf, lvl + 1, path_new_leaf, path_old_leaf)
                .await?;
            let (left_child, right_child) = if path_new_leaf[lvl] {
                (PoseidonHash::default(), next_key)
            } else {
                (next_key, PoseidonHash::default())
            };
            let new_node_middle = Node::new_middle(left_child, right_child)?;
            return self.add_node(&new_node_middle).await;
        }

        let old_leaf_key = old_leaf.key();
        let new_leaf_key = new_leaf.key();
        let (left_child, right_child) = if path_new_leaf[lvl] {
            (old_leaf_key, new_leaf_key)
        } else {
            (new_leaf_key, old_leaf_key)
        };
        let new_node_middle = Node::new_middle(left_child, right_child)?;

        self.add_node(new_leaf).await?;
        self.add_node(&new_node_middle).await
    }

    #[async_recursion(?Send)]
    async fn add_leaf(
        &mut self,
        new_leaf: &Node,
        key: &PoseidonHash,
        lvl: usize,
        path: &[bool],
    ) -> Result<PoseidonHash, MerkleError> {
        if lvl > self.max_levels - 1 {
            return Err(MerkleError::ReachedMaxLevel);
        }

        let node = self.get_node(key).await?;
        match node.node_type() {
            NodeType::Empty => self.add_node(new_leaf).await,
            NodeType::Leaf => {
                let n_key = node.entry().ok_or(MerkleError::EntryNotFound)?[0];
                let new_leaf_key = new_leaf.entry().ok_or(MerkleError::EntryNotFound)?[0];
                if n_key.hex() == new_leaf_key.hex() {
                    return Err(MerkleError::EntryIndexAlreadyExists);
                }

                let path_old_leaf = self.get_path(self.max_levels, &n_key);
                self.push_leaf(new_leaf, &node, lvl, path, &path_old_leaf)
                    .await
            }
            NodeType::Middle => {
                let new_node_middle = if path[lvl] {
                    let next_key = self
                        .add_leaf(
                            new_leaf,
                            &node.child_r().ok_or(MerkleError::ChildNotFound)?,
                            lvl + 1,
                            path,
                        )
                        .await?;
                    Node::new_middle(node.child_l().ok_or(MerkleError::ChildNotFound)?, next_key)?
                } else {
                    let next_key = self
                        .add_leaf(
                            new_leaf,
                            &node.child_l().ok_or(MerkleError::ChildNotFound)?,
                            lvl + 1,
                            path,
                        )
                        .await?;
                    Node::new_middle(next_key, node.child_r().ok_or(MerkleError::ChildNotFound)?)?
                };
                self.add_node(&new_node_middle).await
            }
        }
    }

    async fn add_node(&mut self, n: &Node) -> Result<PoseidonHash, MerkleError> {
        if n.node_type() == NodeType::Empty {
            return Ok(n.key());
        }

        let k = n.key();
        if self.db.get(&k).await.is_ok() {
            return Err(MerkleError::NodeKeyAlreadyExists);
        }

        let node = n.clone();
        self.db.put(&k, &node).await?;

        Ok(k)
    }

    async fn get_node(&self, key: &PoseidonHash) -> Result<Node, MerkleError> {
        if *key == PoseidonHash::default() {
            return Node::new_empty();
        }

        self.db.get(key).await
    }

    #[async_recursion(?Send)]
    async fn walk_internal(
        &self,
        key: &PoseidonHash,
        f: &impl Fn(&Node),
    ) -> Result<(), MerkleError> {
        let n = self.get_node(key).await?;
        match n.node_type() {
            NodeType::Empty => f(&n),
            NodeType::Leaf => f(&n),
            NodeType::Middle => {
                f(&n);
                self.walk_internal(&n.child_l().ok_or(MerkleError::ChildNotFound)?, f)
                    .await?;
                self.walk_internal(&n.child_r().ok_or(MerkleError::ChildNotFound)?, f)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn walk(
        &self,
        root_key: Option<&PoseidonHash>,
        f: &impl Fn(&Node),
    ) -> Result<(), MerkleError> {
        let root_key = match root_key {
            Some(key) => key,
            None => self.root(),
        };
        self.walk_internal(root_key, f).await
    }

    pub async fn graph_viz(&self, root_key: Option<&PoseidonHash>) -> Result<String, MerkleError> {
        let result = RefCell::new(String::new());
        result
            .borrow_mut()
            .push_str("digraph hierarchy {\nnode [fontname=Monospace,fontsize=10,shape=box]\n");

        let cnt = RefCell::new(0);
        let err_in = RefCell::new(None);

        self.walk(root_key, &|n| {
            let k = n.key();
            match n.node_type() {
                NodeType::Empty => {}
                NodeType::Leaf => result
                    .borrow_mut()
                    .push_str(&format!("\"{}\" [style=filled];\n", k.string())),
                NodeType::Middle => {
                    let mut lr = [
                        n.child_l().map(|c| c.string()).unwrap_or_default(),
                        n.child_r().map(|c| c.string()).unwrap_or_default(),
                    ];
                    let mut empty_nodes = String::new();
                    for mut lr in &mut lr {
                        if lr.is_empty() {
                            let mut count = cnt.borrow_mut();
                            let mut tmp = format!("empty{}", *count);
                            lr = &mut tmp;
                            empty_nodes.push_str(&format!("\"{}\" [style=dashed,label=0];\n", lr));
                            *count += 1;
                        }
                    }
                    result.borrow_mut().push_str(&format!(
                        "\"{}\" -> {{\"{}\" \"{}\"}}\n",
                        k.string(),
                        lr[0],
                        lr[1]
                    ));
                    result.borrow_mut().push_str(&empty_nodes);
                }
            }
        })
        .await?;

        result.borrow_mut().push_str("}\n");

        if let Some(err) = err_in.borrow_mut().take() {
            return Err(err);
        }

        Ok(result.into_inner())
    }

    pub async fn print_graph_viz(
        &self,
        root_key: Option<&PoseidonHash>,
    ) -> Result<(), MerkleError> {
        let graph_viz_str = self.graph_viz(root_key).await?;
        println!("{}", graph_viz_str);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{db::memory::MemoryStorage, merkletree::MerkleTree};
    use num_bigint::BigUint;

    #[tokio::test]
    async fn test_merkletree() {
        let sto = MemoryStorage::default();
        let mut mt = MerkleTree::new(sto, 40).await.unwrap();

        mt.add(
            &parse_input("0aa22023480d9a058db4f66c9f98e840742301876584f63fe9a2b4b97f7e76a3"),
            &parse_input("210698f8c003156fde88f936d64904d5fdc95ca0822e5cef83fb63285e328aba"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "12EBE4F75F383EFF2188F5C5C40135C9142121FE859F821B520278BC9699BBB1".to_lowercase()
        );

        mt.add(
            &parse_input("02f09a348ca0a147004d0ab6c0de541b7ac7cb4f032960f3a905b6001065b123"),
            &parse_input("36f3d875"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "24F16B0D251E81DDB4F20B5449B157A3E81AE9001559734289A6E9D755A83347".to_lowercase()
        );

        mt.add(
            &parse_input("139bd12b8d21eae58a6da3ebeaf7a65c17d6196fe30c459f13153503f509df56"),
            &parse_input("1fc6f0be5d5ac35cd21125df9c4b32f48c58e22b842be4e47ba5f9d446ef3b96"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "1B436B631F4C953004CBFF9C49B3E957BB1661B2C1319004781E2526B4BAEC2A".to_lowercase()
        );

        mt.add(
            &parse_input("0a90cbc784161a1897535add33ca874e9561f97a11d388f6d527266efb84647e"),
            &parse_input("0b64f764f250cc7fbfd0be59bd59ee9b80074c18323416197ea3ca036b89e8e6"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "1CFB578E8D45B26C8C9D0D2CC9F5C814F8EDA4A87A09D53714931D0DFD18C86E".to_lowercase()
        );

        mt.add(
            &parse_input("22f90f8064ca4b7cb7a3132661bca4a9f771e6ecc2a8583dcbfcf4f7154787eb"),
            &parse_input("01"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "139C7CB67ECA8AEEB9178CDAD519320FF901AFAA2E6A80E2A18DCBBE89B57C98".to_lowercase()
        );

        mt.add(
            &parse_input("04674a3ca5406de91308af2f8242026fb790380e0f42f50c1d95c47cd99891df"),
            &parse_input("0ceaf9214e0f757d240dc6b3bf8cdcceea57e1fda17333acbf47adffa256f4cb"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "0F88DCF34BEF4E0387A7A1D1FCA1A4D59A70362E904B50F850BD178425FEA9B9".to_lowercase()
        );

        mt.add(
            &parse_input("2837992eb07f6bd3ca095dc712bad8547c08f0fe251aaba82d666d1ab2080a68"),
            &parse_input("28ea04837b911303a62ca23f860da7436814b9b6cf837d4d5188803eb903dad3"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "0A1D6B10F6871382FBB9F1CD0D7D439531853385CAD921131AD845CA57A67CFE".to_lowercase()
        );

        mt.add(
            &parse_input("1567331e690f7f74eb66a837832fad9ac3e0471da8440f73277fe55afbcfa6ee"),
            &parse_input("022b2bf16e61aa91a4147b0587764e1fdb87111a05dd41d84b9146f1ba4ab68c"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "0A6CE7C0FD1A848996D16B7EDC04DB78F7B05DE8B19485FFE789FABBBA474C7B".to_lowercase()
        );

        mt.add(
            &parse_input("0426417929206a345ac0a82cea194619158d14de89e33e17adcd740aab75a008"),
            &parse_input("0f2cdc0d5b21d71e087d11308e5e2c761d101600aea8ab310c3c92a674f53a62"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "2B923008405605D4192A756D56D65E88CF080C8EC281B9BC41513AA3BA277CD2".to_lowercase()
        );

        mt.add(
            &parse_input("1f38d1451232c63e42229d964889c5128751767c8bd0c1bd76401a9ab9956570"),
            &parse_input("13bfd728dc56f8587c57f017af981cb3946acf0d17fef3131957a291cbd6c1da"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "0AB8467C25E8649C85D1099B2280F119C5F69CE556A2D9E967ACDFAD5BB66ECB".to_lowercase()
        );

        mt.add(
            &parse_input("29e179cf1bd1289c8861dab750f4c7776db8b2faf33e906151014c2d3f8037dc"),
            &parse_input("210698f8c003156fde88f936d64904d5fdc95ca0822e5cef83fb63285e328aba"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "1350D31E4CC93776363980E03596B3E49E33B642B96327AB14AC1D8334F329C0".to_lowercase()
        );

        mt.add(
            &parse_input("050bf0665f2bde935a08c44c860378b75d29a254c67fdb597514882e5be92bf7"),
            &parse_input("0d5918dcf6cc5e1faf8218cdd2f623d0dc7760b48532480f3593b1091805affe"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "1075A55164FA277CA7F97CD4571E12DD48E421638F5D25B62725990B21C026DD".to_lowercase()
        );

        mt.add(
            &parse_input("1a4d3ff803880709401abda893c8366d61261b36597d303cbb0637b0c6706ad2"),
            &parse_input("0d2acac3b29bc92413ee31c1b30ae2c67d0c7da986decc910d96872dab6a38d5"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "2D91CA4D64AD562D394A7E2566F573329EBE6F5FD23911878D84E3CF069816FD".to_lowercase()
        );

        mt.add(
            &parse_input("0a983fdfa807fb312f9b4f055f58706edf27b74791449a413af482a393678d93"),
            &parse_input("2158e29f833a8d467089194739d597bbf75c2419e1add198107412855f27f3e8"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "033D2CC01EC8CFC2958F65D53FFF5BA35691523304C43B90D44635AFD83518E2".to_lowercase()
        );

        mt.add(
            &parse_input("1dcf52e4b171d451815c33cbffa091d23daa9f702299ad3ce139f492ad57179d"),
            &parse_input("199991a4b60e8e00"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "12A19E5868CA305632299E930D6AEC08FFF665CE254D8AB4544CA9111384AFE0".to_lowercase()
        );

        mt.add(
            &parse_input("1343db65ec466758e680532c23310ae50892cb94c0c05c825b9b44171933f401"),
            &parse_input("1774c700830f2d92"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "04C0AD1B5E548F09BA5F2237AFC0086DD3A8D547D4799D6CC0149C02631930BD".to_lowercase()
        );

        mt.add(
            &parse_input("0d21ef67a76161105b81395789a61aed1999ac797a81d8a2b577a1058535ee5f"),
            &parse_input("100f280274dc76151a27640f952235e528fb956659cb9043fede59838c96260c"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "022C34841C6ED8F5D5C296F1B4F616E746214BE24AF35187832767502CA5954D".to_lowercase()
        );

        mt.add(
            &parse_input("1c804c9e59f6955fdc4da8f262d8422e8ae3f77bee2df067f48d8ef817d46bb0"),
            &parse_input("08e0ee6d4b4a672aac60341aca9707b2e27c220b3cbca8ea3de6ad17ffccea99"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "1BE5C986AE66B1E4AB0B3DD3F377FD4036A472FD6D40DAAB471E3E6C50D41134".to_lowercase()
        );

        mt.add(
            &parse_input("218df8067628b7b021ea7c31fdbb0813a9c1ef244e502a61c635fb10148cf531"),
            &parse_input("2eb3c38a27a59b1d9fdf2dc054fd5b0a2cda44a0af3043bbe0b3ba7246e64412"),
        )
        .await
        .unwrap();

        assert_eq!(
            mt.root().hex(),
            "0A0262F009FB79CC563F91615901614191A5DF9DD534FC0904B33F5F4801A26E".to_lowercase()
        );
    }

    fn parse_input(input: &'static str) -> BigUint {
        BigUint::parse_bytes(input.as_bytes(), 16).unwrap()
    }
}
