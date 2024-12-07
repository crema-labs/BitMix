use crate::*;
use libsecp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct BitMix {
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
    pub pub_c_x: [u8; 32],
    pub pub_c_y: [u8; 32],
    pub priv_b: [u8; 32],
}

impl BitMix {
    pub fn verify(
        &self,
    ) -> (
        bool,
        Vec<[u8; 32]>,
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
        Vec<u8>,
    ) {
        let (tx_hash, _prevouts, outpoints) = parse_tx(&self.tx_hex);
        let merkle_root = calculate_merkle_root(&tx_hash, self.tx_index, &self.proof);

        let block_hash = calculate_block_hash(&self.block_params, merkle_root);

        let mut pub_c_slice = Vec::new();
        pub_c_slice.extend_from_slice(&self.pub_c_x);
        pub_c_slice.extend_from_slice(&self.pub_c_y);

        let pub_c_bytes =
            PublicKey::parse_slice(&pub_c_slice, Some(libsecp256k1::PublicKeyFormat::Raw)).unwrap();
        let compress_pub_c = pub_c_bytes.serialize_compressed();

        let combined_pub_key =
            point_addition(&self.pub_a_x, &self.pub_a_y, &self.pub_b_x, &self.pub_b_y);

        let script_pub_key = calculate_witness_script_address(combined_pub_key, compress_pub_c);

        assert!(compare_bytes(
            outpoints[self.outpoint_index as usize].spk.clone(),
            script_pub_key
        ));

        assert!(find_block_hash(&block_hash, &self.block_hashes));

        let cipher_text = encrypt_ecies(&self.pub_a_x, &self.pub_a_y, &self.priv_b);

        (
            true,
            self.block_hashes.clone(),
            self.pub_a_x,
            self.pub_a_y,
            self.pub_c_x,
            self.pub_c_y,
            cipher_text,
        )
    }
}

mod tests {
    use super::*;
    use libsecp256k1::SecretKey;
    use serde::{Deserialize, Serialize};
    use std::fs;

    #[test]
    fn test_bitmix() {
        let input_file = "/Users/yash/Desktop/crema/bitmix/inputs/test_1.json";

        let file_content = fs::read_to_string(input_file).unwrap();
        let bitmix_input: BitMix = serde_json::from_str(&file_content).unwrap();

        let (verified, _, _, _, _, _, _) = bitmix_input.verify();

        assert!(verified);
    }
}
