mod btc;

use alloy_sol_types::sol;
use ecies::encrypt;
use libsecp256k1::PublicKey;
use sha2::{Digest, Sha256};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        bytes32[10] memory block_hashes;
        bytes32 pub_a_x;
        bytes32 pub_a_y;
        bytes memory cipher;
    }
}

pub struct BlockParams {
    pub version: [u8; 4],
    pub previous_block_hash: [u8; 32],
    pub timestamp: [u8; 4],
    pub n_bits: [u8; 4],
    pub nonce: [u8; 4],
}

fn sha256_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn calculate_witness_script_address(
    pubkey1: [u8; 33],
    pubkey2: [u8; 33],
    relative_locktime: i64,
) -> Vec<u8> {
    let witness_script = construct_witness_script(pubkey1, pubkey2, relative_locktime);

    let script_hash = sha256_hash(&witness_script);
    // P2WSH address
    let mut script_pubkey = vec![0x00, 0x20];
    // pre pend 0020 to the pubkey
    script_pubkey.extend_from_slice(&script_hash);
    script_pubkey
}

fn construct_witness_script(
    pubkey1: [u8; 33],
    pubkey2: [u8; 33],
    relative_locktime: i64,
) -> Vec<u8> {
    let mut script = Vec::new();

    // OP_IF branch
    script.extend_from_slice(&[0x73]); // OP_IF

    // First public key hash branch
    script.extend_from_slice(&[0x76]); // OP_DUP
    script.push(0x21); // OP_DATA_33
    script.extend_from_slice(&pubkey1);

    // OP_ELSE branch
    script.extend_from_slice(&[0x67]); // OP_ELSE

    // Relative locktime check
    script.extend_from_slice(&relative_locktime.to_le_bytes());
    script.extend_from_slice(&[0xb2]); // OP_CHECKSEQUENCEVERIFY
    script.extend_from_slice(&[0x75]); // OP_DROP

    // Second public key hash branch
    script.extend_from_slice(&[0x76]); // OP_DUP
    script.push(0x21); // OP_DATA_33
    script.extend_from_slice(&pubkey2);

    // Finalize script
    script.extend_from_slice(&[0x68]); // OP_ENDIF
    script.extend_from_slice(&[0x88]); // OP_EQUALVERIFY
    script.extend_from_slice(&[0xac]); // OP_CHECKSIG

    script
}

fn calculate_merkle_root(
    tx_hash: &[u8; 32],
    tx_index: u64,
    merkle_proofs: &Vec<[u8; 32]>,
) -> [u8; 32] {
    let current_hash = *tx_hash;

    for proof in merkle_proofs {
        // Concatenate current hash with the proof hash
        let mut to_hash = Vec::new();
        if tx_index % 2 == 1 {
            to_hash.extend_from_slice(proof);
            to_hash.extend_from_slice(&current_hash);
        } else {
            to_hash.extend_from_slice(&current_hash);
            to_hash.extend_from_slice(proof);
        }
    }
    current_hash
}

// Helper function for double SHA-256 hashing
fn sha256d(data: &[u8]) -> [u8; 32] {
    let first_hash = sha256_hash(data);
    sha256_hash(&first_hash)
}

fn calculate_block_hash(block_params: &BlockParams, merkle_root_hash: [u8; 32]) -> [u8; 32] {
    let mut to_hash = Vec::new();
    to_hash.extend_from_slice(&block_params.version);
    to_hash.extend_from_slice(&block_params.previous_block_hash);
    to_hash.extend_from_slice(&merkle_root_hash);
    to_hash.extend_from_slice(&block_params.timestamp);
    to_hash.extend_from_slice(&block_params.n_bits);
    to_hash.extend_from_slice(&block_params.nonce);
    sha256d(&to_hash)
}

fn encrypt_ecies(pub_a_x: &[u8], pub_a_y: &[u8], data: &[u8]) -> Vec<u8> {
    //concatenate the x and y coordinates of the public key
    let mut pub_key = Vec::new();
    pub_key.extend_from_slice(pub_a_x);
    pub_key.extend_from_slice(pub_a_y);
    encrypt(&pub_key, data).unwrap()
}

struct Prevout {
    txid: [u8; 32],
    vout: u32,
}

struct Outpoint {
    amount: u32,
    spk: Vec<u8>,
}

fn parse_tx(tx: &[u8]) -> ([u8; 32], Vec<Prevout>, Vec<Outpoint>) {
    let (offset, prevouts) = parse_prevouts(tx, 6);
    let (outpoint_offset, outpoints) = parse_outpoints(tx, offset);
    let tx_id = calculate_tx_id(tx, outpoint_offset);

    (tx_id, prevouts, outpoints)
}

fn calculate_tx_id(tx: &[u8], offset: usize) -> [u8; 32] {
    let tx_without_witness = [&tx[..4], &tx[6..offset], &tx[tx.len() - 4..]].concat();
    let tx_id_in_natural_byte_order = sha256d(&sha256d(&tx_without_witness));
    tx_id_in_natural_byte_order
}

fn parse_prevouts(tx: &[u8], start_offset: usize) -> (usize, Vec<Prevout>) {
    let mut offset = start_offset;
    let (bytes_length, num_inputs) = decode_varint(tx, offset);
    offset += bytes_length;

    let input_count = bytes_to_u32(&num_inputs);
    let mut prevouts = Vec::with_capacity(input_count as usize);

    for _ in 0..input_count {
        let (new_offset, prevout) = parse_single_prevout(tx, offset);
        offset = new_offset;
        prevouts.push(prevout);
    }

    (offset, prevouts)
}

fn parse_single_prevout(tx: &[u8], start_offset: usize) -> (usize, Prevout) {
    let mut offset = start_offset;
    let prevout = Prevout {
        txid: tx[offset..offset + 32].try_into().unwrap(),
        vout: u32::from_le_bytes(tx[offset + 32..offset + 36].try_into().unwrap()),
    };
    offset += 36;

    let (script_sig_length, script_sig_value) = decode_varint(tx, offset);
    offset += script_sig_length;
    offset += bytes_to_u32(&script_sig_value) as usize;

    offset += 4;

    (offset, prevout)
}

fn parse_outpoints(tx: &[u8], start_offset: usize) -> (usize, Vec<Outpoint>) {
    let mut offset = start_offset;
    let (outputs_length, num_outputs) = decode_varint(tx, offset);
    offset += outputs_length;

    let output_count = bytes_to_u32(&num_outputs);
    let mut outpoints = Vec::with_capacity(output_count as usize);

    for _ in 0..output_count {
        let (new_offset, outpoint) = parse_single_outpoint(tx, offset);
        offset = new_offset;
        outpoints.push(outpoint);
    }

    (offset, outpoints)
}

fn parse_single_outpoint(tx: &[u8], start_offset: usize) -> (usize, Outpoint) {
    let mut offset = start_offset;
    let outpoint = Outpoint {
        amount: bytes_to_u32(&tx[offset..offset + 8]),
        spk: tx[offset + 8..].to_vec(),
    };
    offset += 8 + outpoint.spk.len();

    (offset, outpoint)
}

fn decode_varint(data: &[u8], offset: usize) -> (usize, Vec<u8>) {
    if data[offset] < 0xfd {
        (1, data[offset..offset + 1].to_vec())
    } else if data[offset] == 0xfd {
        (3, data[offset + 1..offset + 3].to_vec())
    } else if data[offset] == 0xfe {
        (5, data[offset + 1..offset + 5].to_vec())
    } else {
        (9, data[offset + 1..offset + 9].to_vec())
    }
}

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}

// compare all elements of two byte arrays
fn compare_bytes(a: Vec<u8>, b: Vec<u8>) -> bool {
    a.iter().zip(b.iter()).all(|(a, b)| a == b)
}

// secp256k1 point addition
fn point_addition(pub_a_x: &[u8], pub_a_y: &[u8], pub_b_x: &[u8], pub_b_y: &[u8]) -> ([u8; 33]) {
    let mut pub_a_slice = Vec::new();
    pub_a_slice.extend_from_slice(pub_a_x);
    pub_a_slice.extend_from_slice(pub_a_y);
    let pub_a =
        PublicKey::parse_slice(&pub_a_slice, Some(libsecp256k1::PublicKeyFormat::Full)).unwrap();

    let mut pub_b_slice = Vec::new();
    pub_b_slice.extend_from_slice(pub_b_x);
    pub_b_slice.extend_from_slice(pub_b_y);
    let pub_b =
        PublicKey::parse_slice(&pub_b_slice, Some(libsecp256k1::PublicKeyFormat::Full)).unwrap();
    let pub_c = PublicKey::combine(&[pub_a, pub_b]).unwrap();
    let pub_c_bytes = pub_c.serialize_compressed();

    pub_c_bytes
}

fn find_block_hash(block_hash: &[u8; 32], block_hashes: &Vec<[u8; 32]>) -> bool {
    block_hashes
        .iter()
        .any(|hash| compare_bytes(hash.to_vec(), block_hash.to_vec()))
}

mod tests {
    use super::*;

    #[test]
    fn test_block_header_hash() {
        let block_params = BlockParams {
            version: hex::decode("04e00020").unwrap().try_into().unwrap(),
            previous_block_hash: hex::decode(
                "4be80184cc04d777daad1189724bc32a949e04601ebf02000000000000000000",
            )
            .unwrap()
            .try_into()
            .unwrap(),

            timestamp: hex::decode("881c2966").unwrap().try_into().unwrap(),
            n_bits: hex::decode("db310317").unwrap().try_into().unwrap(),
            nonce: hex::decode("2b1d1f06").unwrap().try_into().unwrap(),
        };

        let block_hash = calculate_block_hash(
            &block_params,
            hex::decode("78ce8a1195d00b58c530046ec369868aa4cc856bf139ef2636192ced886ed412")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            block_hash,
            <[u8; 32]>::try_from(
                hex::decode("aea988eb825ea493f3ae97679b674311f50922adcbd201000000000000000000")
                    .unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_encrypt_ecies() {
        let x = hex::decode("179aabeb27c929d78421b74bee75820846561d9b3b1bd0ccc2dc3d1aa7157186")
            .unwrap();
        let y = hex::decode("27bd97ac055c937d0264001ad0af382313991b2e7cd564a76ec3d550bce2a50d")
            .unwrap();
        let data = b"Hello, world!";
        let encrypted_data = encrypt_ecies(&x, &y, data);
        println!("{:?}", encrypted_data);
    }
}
