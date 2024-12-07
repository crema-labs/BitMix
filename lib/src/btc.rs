use crate::*;
use libsecp256k1::{PublicKey, SecretKey};
struct BitMix {
    pub tx_hex: Vec<u8>,
    pub proof: Vec<[u8; 32]>,
    pub tx_index: u64,
    pub outpoint_index: u64,
    pub block_hashes: Vec<[u8; 32]>,
    pub block_params: BlockParams,
    pub pub_a_x: [u8; 32],
    pub pub_a_y: [u8; 32],
    pub pub_b_x: [u8; 32],
    pub pub_b_y: [u8; 32],
    pub priv_c: [u8; 32],
}

impl BitMix {
    pub fn verify(&self) -> (bool, Vec<u8>) {
        let (tx_hash, _prevouts, outpoints) = parse_tx(&self.tx_hex);
        let merkle_root = calculate_merkle_root(&tx_hash, self.tx_index, &self.proof);

        let block_hash = calculate_block_hash(&self.block_params, merkle_root);

        let sec_key = SecretKey::parse_slice(&self.priv_c).unwrap();
        let pub_c = PublicKey::from_secret_key(&sec_key);
        let pub_c_bytes = pub_c.serialize_compressed();

        let combined_pub_key =
            point_addition(&self.pub_a_x, &self.pub_a_y, &self.pub_b_x, &self.pub_b_y);

        let script_pub_key = construct_witness_script(combined_pub_key, pub_c_bytes, 72);

        assert!(compare_bytes(
            outpoints[self.outpoint_index as usize].spk.clone(),
            script_pub_key
        ));

        assert!(find_block_hash(&block_hash, &self.block_hashes));

        let cipher_text = encrypt_ecies(&self.pub_a_x, &self.pub_a_y, &self.priv_c[0..32]);

        (true, cipher_text)
    }
}
