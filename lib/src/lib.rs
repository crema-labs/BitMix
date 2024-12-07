pub mod btc;
use std::{cmp::min, env::current_exe};

use alloy_sol_types::sol;
use ecies::encrypt;
use libsecp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        bytes32[1] memory block_hashes;
        bytes32 pub_a_x;
        bytes32 pub_a_y;
        bytes32 pub_c_x;
        bytes32 pub_c_y;
        bytes memory cipher;
    }
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
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

fn calculate_witness_script_address(pubkey1: [u8; 33], pubkey2: [u8; 33]) -> Vec<u8> {
    let witness_script = construct_witness_script(pubkey1, pubkey2);

    let script_hash = sha256_hash(&witness_script);
    // P2WSH address
    let mut script_pubkey = vec![0x00, 0x20];
    // pre pend 0020 to the pubkey
    script_pubkey.extend_from_slice(&script_hash);
    script_pubkey
}

fn construct_witness_script(pubkey1: [u8; 33], pubkey2: [u8; 33]) -> Vec<u8> {
    let mut script = Vec::new();

    // OP_IF branch
    script.extend_from_slice(&[0x63]); // OP_IF
    script.extend_from_slice(&[0x21]); // OP_DATA_33

    // First public key hash branch
    script.extend_from_slice(&pubkey1);

    // OP_ELSE branch
    script.extend_from_slice(&[0x67]); // OP_ELSE

    // Relative locktime check
    script.extend_from_slice(&[0x01, 0x48]); // 72 is hardcoded for now
    script.extend_from_slice(&[0xb2]); // OP_CHECKSEQUENCEVERIFY
    script.extend_from_slice(&[0x75]); // OP_DROP

    script.extend_from_slice(&[0x21]); // OP_DATA_33
                                       // Second public key hash branch
    script.extend_from_slice(&pubkey2);

    // Finalize script
    script.extend_from_slice(&[0x68]); // OP_ENDIF
    script.extend_from_slice(&[0xac]); // OP_CHECKSIG

    script
}

fn calculate_merkle_root(
    tx_hash: &[u8; 32],
    mut tx_index: u64,
    merkle_proofs: &Vec<[u8; 32]>,
) -> [u8; 32] {
    let mut current_hash = *tx_hash;

    // If using Bitcoin's byte order convention
    current_hash.reverse();

    for proof in merkle_proofs {
        let mut proof_hash = *proof;
        proof_hash.reverse(); // If using Bitcoin's byte order convention

        let mut to_hash = Vec::new();
        if tx_index & 1 == 1 {
            to_hash.extend_from_slice(&proof_hash);
            to_hash.extend_from_slice(&current_hash);
        } else {
            to_hash.extend_from_slice(&current_hash);
            to_hash.extend_from_slice(&proof_hash);
        }

        current_hash = sha256d(&to_hash);
        tx_index >>= 1; // Update index for next level
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
    let mut tx_id_in_natural_byte_order = sha256d(&tx_without_witness);
    tx_id_in_natural_byte_order.reverse();
    tx_id_in_natural_byte_order
}

fn parse_prevouts(tx: &[u8], start_offset: usize) -> (usize, Vec<Prevout>) {
    let mut offset = start_offset;
    let (bytes_length, num_inputs) = decode_varint(tx, offset);
    offset += bytes_length;

    let input_count = bytes_to_u32(num_inputs);
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
    offset += bytes_to_u32(script_sig_value) as usize;

    offset += 4;

    (offset, prevout)
}

fn parse_outpoints(tx: &[u8], start_offset: usize) -> (usize, Vec<Outpoint>) {
    let mut offset = start_offset;
    let (outputs_length, num_outputs) = decode_varint(tx, offset);
    offset += outputs_length;

    let output_count = bytes_to_u32(num_outputs);
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
    // let outpoint = Outpoint {
    let amount = bytes_to_u32(tx[offset..offset + 8].to_vec());
    // };
    offset += 8;

    let (script_pubkey_length, script_pubkey_value) = decode_varint(tx, offset);
    offset += script_pubkey_length;
    let length_value = bytes_to_u32(script_pubkey_value) as usize;
    let spk = tx[offset..offset + length_value].to_vec();
    offset += length_value;

    let outpoint = Outpoint { amount, spk };

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

fn bytes_to_u32(data: Vec<u8>) -> u32 {
    let mut res: [u8; 4] = [0; 4];
    let l = min(data.len(), 4);
    for i in 0..l {
        res[i] = data[i];
    }
    u32::from_le_bytes(res)
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
        PublicKey::parse_slice(&pub_a_slice, Some(libsecp256k1::PublicKeyFormat::Raw)).unwrap();

    let mut pub_b_slice = Vec::new();
    pub_b_slice.extend_from_slice(pub_b_x);
    pub_b_slice.extend_from_slice(pub_b_y);
    let pub_b =
        PublicKey::parse_slice(&pub_b_slice, Some(libsecp256k1::PublicKeyFormat::Raw)).unwrap();
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
        println!("{:?}", hex::encode(encrypted_data));
    }

    #[test]
    fn test_parse_tx() {
        let tx = hex::decode(
            "0100000000010f50cdd9023da9e04bdf6eff6a76992bad58f5e6e37ba270bd61892c5006189b1f0500000023220020d0885c6ce48a9dc58c62820eab31d9846344f10a10f43b98d343f956dcb99a5efffffffd72e8382a8a2f460182b4d48bc8261b0fe68df5b0a89628254ebba998325521760100000023220020ee045c5e594598e2ebb6e2d3e962cb6204c48fddf9f2b401717643f9669eef0afffffffdd98c3408f2639d2eb23f9fb9c83b557f5e9023e996525e18390ead40638caf0c01000000232200209391ba1830f313ffdb33569226b8025a7eb11b850483090913ea37d4d987e05cfffffffd2ed0d6df1b099eac2516ac02eb7e26460aaa9d42343acb5e24c088105b7db82500000000232200203dea5697a6618f836ac1c27a899af88614fd56edaa7ab524646049553e8f827bfffffffdbc7e7a607925bbe7099dfad29682d2689ff7245285f6742cda603ef92c95c46b3d0000002322002026f542f6a80ecc733df291d76a3e727704abfa37c0a73f02afb743de963e282afffffffdf2401ab7e6a387e95e7688cb9349a44840fbf3f246c9d02c1a05cd8241683ab701000000232200202ecd6f4d19e7b581866e5d476ad913aa240f7b12ea458e079f95eca532ca36e4fffffffdd8f89a1fc78be9ffa92b4aa10bba17c8eee4888c6dc86a3aefce82b97459139401000000232200202b08b56d3ac130bc67c845b950f2d7b793f3d41e4f6b132757b288c08ba9541bfffffffd12bee32499f51306e4818ee7c1514684702d15d02ffc0f427ea4a31b74bc6775010000002322002093f04011310e1141a69686b691ed8b258705c44b08f3a21cc2afc8f6cc1ea5cdfffffffd8366bb4d45b2bb0101d153684d551c5c9cf7fb6305165af9f1a1508fdc08048b0100000023220020a0e26c5156d4c201fde159e8b5d1a9b94231794b20480a52af19aff0f53b3cd1fffffffda91347b64c87c389095b81d4260bbe4a4f308d0c0851723c3125099b5e6e658f0100000023220020d4126d5960c175f120051e0a2679bdabe4644fbaa572084c57edea18f50de204fffffffdd297d9d2baed51eeb9f1c6466f780e78f338ec674e4c7ad9a7c87236289f6b65010000002322002044e1ab091d24c912fe55dbacb25afada0a16c6eb37af2359fefd6a007ff92f37fffffffd524b5094eee4a84a934c02ab5eed5b0dbdf2df2c619f52fff47dd7e9ff96157701000000232200209237385674c06da661f24b00d17a47c81f21e084fb8e5f136b71f98bba818d99fffffffd0904a386e8352497ea3fce0d4253e469363fa092e918a5dc9703a5c28f559a440100000023220020753de02ce306cba91b8561db6aba59715790f599fda8968e8f204bfc264b77a0fffffffd235090f665e624fb2fd68e6daea4312959f723688e38e01a506315564e3a030001000000232200202d55bb8083a63959193f1d3d5c4846285c885ef788d02876057d18de4a182b06fffffffd41fbce0ef0353dc7bf53da4124b22853f8f6a1cedabd3c03aa12fbdad3208b310100000023220020f71b1413733cfd003dd3528b49895ca330d2a6261342d76afe28180280259057fffffffd023b32f301000000001976a9144e947ede84b54b71e13f08b128d1903bbbee707488ac68c425000000000017a9145257526fd48c320814052df11bc013a6dd18c3698704004830450221008e9ac69f05b6d909d61dae30caacfe9993a4f478a9fd13b79de3ee4bcbc7901b022067c470ff99ae41cd1f81999175e698d68f0b28aec5d601b9f3beee87c5fa7e2e0147304402204517dbb4ac33b088f6eaf6ff9b9ade958541b1f2091814b4da6019b7af138cbd02207e0c8c695898f4260c91e36c4c84cd711da3be3fe43b951de0aaa57650d580b8018b52210206483402897547d3de107448e55d457990c75020079a6685e43ec55dc1d5b613210287c536904edf4f3eab70539336988b1476f68056ea411180c67205e3b64170042102c1fceafeaf2706331065aa16dbe584821d105157a70a51091621024293a1e54021035849e5dda05b486eb5d0a28d1b3f603918eca7cf2ec503f9b80597a57940bdfe54ae0400483045022100a9d69f657089c06e23b9725e5c28d115587743364d100442208293a7589aef670220283f07cb2bb337cf5516588c0d599344bac3aab1fad2db839c96b04da52e396e01483045022100814be7a816b4d72db6fe8108f6131501106ef5cfc746f997d7df2c8d02bd015d022076b7d9c5c065de8d1fae4870cb3b5e42cbd6806454246c77553dbf98999ed8da018b522102c48b1f97d1156516893ddad56fdcbcf19d6f6c9b83183174af756fc5b9b5a1b3210329cee1073ff594c45a386de297652e5e64e470616f410ff4703cc9604bb57484210330092ac57216b1ddb6e509a7107f759ca1c127bd88c051bc3c85fc4d774a9acf2103c2a817a3e2418a7d5a846b08f9cfa18921d0e3d5d918d2c2104f459139f6376a54ae040047304402205899c0a4ed16a74001c98effd622f4b76048f39e1c045055cab8bf093e5516fb0220380eb808cde94412955fceae3bda38eddbc0345c56271237f3f95b7907e215b6014730440220051c587784f6403b65149576c8fa139f67eda100db946ce24cf5befe6fa0a8c1022008bdb1cff2ee1b94e8eb058f7d1ffe8be5a7dd53477d28d3054b3ee5671e0117018b5221022888142686aeb3d4c9fb4bceeb773383dfbc15cd73baae05272b96d6232e063921026af873aebf062c56616691981e86c96ca75d03c771baddbe6541d06ca7b1e61221026bccbc442fd69adcc293fa466906894ae833d15b0055e32c2fdeff8f84508f612103eaceac7ca9a0352c6e8794142e02d496f0a795fa7312779857091561623d445254ae0400473044022012b20d12cf7ab65301ec7b6b15aa06c39586e74d31947165597c2c6d23701dd002206128008a5ff62ecbf435b3d646b4ed331bce145f72d5c937451bbebbc0156f2a01483045022100cfea8e2d37183825b4ca6ed93836e12c79d4b6ab936172a7a44f9a5d29eec0e8022044e6ed3c6fd5a5f915762291feed8d09263fc25cf40710f72441754d81606dc2018b522102012df37f58d8e9dc7ec5b65fac9b521782517f73b2a43402994432cdb30262392102db733204538ed6c32ecaae29b9d07d6a29330df3c6bc1148821cce87c4768ca621036ef8d16cb81409ef46bd14c513b72634f55e84cf3451af7adbe0152ba8d5a13c2103a7c318dd6cdbb957934adcd0b02569311ec2d1f043f3cf0f2eabb2db1186eaa354ae040047304402201674cadf26d66c2516ea6b25cef5c7c107741e9e63c24b015b0d1185316cb4a202207953ef4207a1fd45e1fb1b9d04f7daacfa6dbb56423a2b612cfad7d5aad0784101473044022005063b8d9ba7cd5f1e701613fe3b55bda6b179337f4c2902d0b35a3d3ee7d75402200b3dfadb7753a20686f8cdeb109a137555ff0e38219c261fcbf1fdfddbc62522018b522102b2ce0691850874586e598e995baba74f2829f174efabebcd533c9153f7862c3921034b8787586cd3a92602c63bf10fd03f02947c4819db7c9d0f4722472b780c681b2103d1443c40f97b6019541f3eb7f449e54a9d6df385df1c00cab049e297869859802103d3b8b64d84a6a7b1286145b7ccc315227713bd57ae2a38420b0a1ab282be498054ae040047304402207ba7b378aedd65f49c1075d4ee161b13e257d30fd7e362ce89f23e82f4490eac0220557c68f7b17f8f5de601cbf9821f2d757d902407d1e6e1c1cb9b678d9d343e4b0147304402202124afb47873c049dbf5e31b2279b22c93afded4125b45fccd31216b009675ae02206e72f05c32f998fada7d161fd6a7ede5866afc4d4771b3fb23e556fb823381c1018b5221020e031c12d6999ed4dc18f0d5fcc05f6293ea5cbffe242ae22766dc4f5f8c33df210238762bbe88c06e30ba49232b9eb7544f45d557b2d2f69fc789f71b5ea70f8c1621023bc8d089159531c98596fa0b89cc5bd2f63e872b8ef34e4333897c36c3c1aa4e210252938b8983441cdfc7c6b923786191d1910059e9d247c6d3a7f98dd277c7c46c54ae0400483045022100f1ce4fb8ba9608ef3ab510778af55b15badaee52e3d8353531f3811ef771d44102204ac3006f5bd61e6fd823cb2ea508202a3354579d6d573bef9a2745606b97b26901473044022040e454317c39cf09ce55143dae350c800513d0d81be02731e980b24e39abba8102205e3686b5d416fa4fa57110f9f46b48248aa3d2fd2db47eafcccaa6cc74be697f018b52210208ec0e9d524060606de48dc0c29b1b931f41f39bc891c26053fc281cca7da4be210231d3fbf9603dbee48b970503705f6a689db4199a45b1a692526b840107cd41ac2102b703a21c7a3c04df9ae16f82a93b92e372bf7c8c160f670b8838f728682f06672103510b5db574607fd421eff7b5c2ef0cd0187471c7b7951df5b7b2453ac615d92354ae04004830450221008d7da6b48d8739cda1a3663c4521f330022511d22dd725eebde78935f52e0d5502207be847c02d0e2d723b802418a02d263d196aaa0b2b9395908d32315827e704e601483045022100ca7d17f9b553832f515d205b7c9066b19812c64dbbb41a263bf19e3770f9c44c02200c8198629a06da4060127ef9ec4dd40eff0a9bdfe1209a0c8210cc07b995f95c018b5221027af9675eb9c00c55ed621a13afe434747669e9952fe6cadc1918752b61ee040321028461c261e82312bfa7938b1ac7e14afcde55313a110adc7f9da63965ebcb8856210323da0f630f003fba749a66e8277cc4ec79d52a5a142658b3123ddd27c5cc58ac21034c70765ed671d357a44d2b6bf5533d9117951cc6ac6d2ad0d676d940d80ede5554ae0400483045022100a37df1d10f01423bf4b0c70840f8438d01fee4854f1b13d7af9f899bbba039850220308d1b1370a3188cb88c4a9b400dd16d100e9a4259ba042b1983743038cdae780147304402206826f383bc26bb1d573b8ee1ee1355a14436a8c21b033104a5cdbe317702914c02206878526329bea120d95b9eb16c89f69a757bbd8f696c771e326c5c545e61a2a2018b522102238edcbfb8f216b510ebc308d1bf6e033e91a0266bd024b0df750d01c7c795912103164761e178493788fa69f34836839aa735c493d90ab48169088ccdb6958dc22121036be437f802ddfa5bc0ada99228b8cc9ae79b998e9b00568bd01b457a4b2739562103dc6934a8cd9244c7cc3f40286513e9bffe6ea1356babb21a5fb3c218978d11a454ae0400473044022046875f003c063d5ba91578742a980b7d915c75d2a5c1372374f186c082c788d702202d5789c8ebd37a7c76034dd68bd8f3ffdb39f0d37068d2236ebfa6f05dcf118401473044022061be9546bf9b72fb0fe1afc2b78beb377cf0b341a43ae37048a71825ca9d6cfe0220419c2cc971ff6a9ece2cc617d64fd16d04eb164e3b8eec9857d71fc203bf6477018b52210222255606f8e0d056122331066b238620776f67de0803c0e4a37c9d40da5558bf2102771afc4eba0f9a06fd374eb059dacb493a5f0912175ce60089434279674afa0a2102b30d3d7abbc0850a995ae42e25f37f3002188df9702b9bf893a8d5c78ef68e9a21037ec0365d161cc2c2cdc6d6bd6e548af2f8e641923d2a473d4ad506b5e3e7c44254ae040047304402206cfdfe12d617272c42d803f277694591016929d7e2a60bb91ca2abe51d27d88202207f0f7086c5aea92a6c4ad0e25055521a05257832bf8b57542371e9ee1284788b0148304502210094d7388fa53101f818c6df472de3e1d87232e8fa03920481d11b6ab86b9f42db02202272375faafefa6d39de558e4cfacc1ffaddb228742502f24ae52b663b4926a0018b5221027ba61c174ac072a8ec54846573b88a7dd301c4d7138c5b43dc1995644e87905b21031da360540aa3e362339f0ba8be507c8851afa7de97d341e8d0035d329075b64921038978e965c17be3633f235d939cb50b740655b4c2c23b8dfb73d807f28c58486c210389a008eaefc80c7b42b15adc2fa51c625c55f46ffe7167e4aacb51763d49fc2254ae040048304502210096f2005922d97cbc7a0c023d75eef310f6cd3bdf765b7ee264b612bb3e7cea9502205da4afd12a7b190ff6559d23c9e06ba9bd76b88e39adc87dc2470b7e5e2422ec01483045022100c7196c8ca07dfac6295723efd429b7dfdc8348af0ade888f6e2d77520df6f3c1022009b31a9084290f7e637dd46a090109d99b5e2e109972594883f34beab46982b3018b5221027a02d89150cfc6ec528539dd5dbefe99855d178c81c656572541c05b3b1ef59b210291ca3b2d9b937a5337627ffc838d247f85dfadb7221437d2d205101dfb2ea0992103261076c5e895e4befc28f3654550ce4267363c1dda52a11dfdc6941c3982d602210348f91d199c69bc0de0d7b01cf66035bca19e8358e9f30a6c6d529f9ee777ad4854ae040047304402205b28cb2e9df62eaffc26ed6ff5aba2ec6c4d22a2bbc173db173666660d1cf3ee022034e0f2fada30f7e9054fcfb853b5818ea6e3735704b946a534f44c38fe02c10701483045022100877506786acf8bee8ed2a235f9c454138c63cd0ebfe0a06098f98f412098295102203a5759ee5dac28e6daa2388e0cfcd81be31dfbaae5af26ece8ff44566f2ab0dd018b5221020ba9d423baa04d003308c7cc45d2a1efed23ff22f4ef118c2e8b79f91b87045421021f551c51a218229aa9e17f9b68b1dd5d2c0c3696ae5dc646c5ce8e27e5f8168221026d9a1277727955c20c3c70fc13b85356ba5841af442bb373b0bef62fc5bb7b0121036ef9fedbb32ef98185eb5c484d6b3a01f7f8770664547fab388d8e212eaae31654ae04004730440220705a72e7b62cdb329989c8c6f7da37593e10970892c7dfe55b2f82cc4e5aba5902203b5d743f9e3dcf3edec2e48dfd2bb96d6d8bad08dbb36cac950471030141a64201483045022100f74a6bd037618e2662a132fdfaa1023f5b1f70ac20dc89711ac512d4aa3e2b3702200128aa85fb723c30dbbb7978d3b70181c52ed397a9b7dbe29de62fffa9a3b147018b5221026a9a650347443a5c93daeadc04267e4e2a63a200deaac6e3b915032217cd8a242102957686fcfc52e58237707e190d58475d186bffa28c4cd38df8c42793da4d8a062102ccb20e3f4b27b144fab069fff0076fd8b00b77e67d3981684832bd171d92ca58210311ad80a0b7819b15f46b83d7c8c4294f043a028e6cea3cbc51adfa7c421fa29054ae0400483045022100f4949855db4a4fe3232f8156051dc18f3b026bcc3938614eaeebd1f99a79bfa1022076c9a23a6281176853d4f2027b021d1d13d16464c7205092e08a5d8401ec7f6a01483045022100d067a088f3d9d5c5edc565773900a9b66a175117603634e57457411e461ec02502206217449077602d52ec7f20baf77f92e4a7312afec348c234ac3766817bb86796018b5221027370ec93cf4b23916002ff3ecb9fc453701db3aa0484bad12dab4898b9fbf068210294755be859edde1fac00c6abf592157715efd854e7ede89190c6b2de1e5fdb5e2103635e78298642dda7366c07be26d9064375d2b07072bcd42459e3931ae808b3c02103a4ef95ee87f92b737ba9a31573b7aa3847a641bd41b18c91a7811e1b35d1d03a54ae00000000"
        ).unwrap();

        let (tx_id, prevouts, outpoints) = parse_tx(&tx);

        assert_eq!(
            tx_id,
            <[u8; 32]>::try_from(
                hex::decode("86d2c82916152317e268ceb8cd3b789b766aaa522540b0b4bc6b6fbc5b836430")
                    .unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_calcualte_witness() {
        let priv_key_a =
            hex::decode("d66d39b59857abe6a54dca112c0addf0c5284c80fc35bc100683a982a64c641d")
                .unwrap();
        let priv_key_b =
            hex::decode("6a601bee1adb9c483c99ea59a6bf511cb7d4a688287bb0fe7753d1890d2b3f82")
                .unwrap();
        let priv_key_c =
            hex::decode("17106cb646a874c8f9ca45b2982d328f207ce091c51b3a005177096b4ba39e27")
                .unwrap();

        let sec_key_a = SecretKey::parse_slice(&priv_key_a).unwrap();
        let pub_a = PublicKey::from_secret_key(&sec_key_a);

        let sec_key_b = SecretKey::parse_slice(&priv_key_b).unwrap();
        let pub_b = PublicKey::from_secret_key(&sec_key_b);

        let sec_key_c = SecretKey::parse_slice(&priv_key_c).unwrap();
        let pub_c = PublicKey::from_secret_key(&sec_key_c);


        println!("pub_a: {:?} pub_b: {:?} pub_c: {:?} {}", pub_a.serialize()[32], pub_b.serialize()[32], pub_c.serialize(), pub_c.serialize()[32]);

        let pub_ab = PublicKey::combine(&[pub_a, pub_b]).unwrap();

        let script_pubkey = calculate_witness_script_address(
            pub_ab.serialize_compressed(),
            pub_c.serialize_compressed(),
        );

        assert_eq!(
            script_pubkey,
            hex::decode("00208ac829f2937b1f8277c3f41f5e1d1f6045ed6069eb67a07005194f6c50cfedec")
                .unwrap()
        );
    }

    #[test]
    fn test_block_hash_generation() {
        let proof: Vec<[u8; 32]> = vec![
            hex::decode("c86b34eae2c4d34f50e5f4584a03b639b902e906b79e0b7312b5227586d00193")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("60071a46e915376d31090e0084449bf165d43f161c15d789341449edb98b3fa8")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("1e3a328b1c4f211256432720a74d6114e685f199c684c96965834a0d7e14c61b")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("59878d1818167350db05a0282e77f95d06e2af7c1beae7a9a23b3a20a11e81fd")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("943220c1003504f9c05dfe61cbdc276765ee0ec58674014e88b14dbee67ad4a0")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("0608c4b3c9df707b2d58c30ac3a6444b2f6a920e404bc3b53397d88d79bfcef1")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("7019dbeef536b297a4da700441fa41a7967d4c24f158a71c67efe96e2529cf11")
                .unwrap()
                .try_into()
                .unwrap(),
        ];

        let root = calculate_merkle_root(
            &hex::decode("9985744f9eb0f18589cf4267c4c2c98dd76d0c4eac44df284f3a4e3db69bcc1a")
                .unwrap()
                .try_into()
                .unwrap(),
            4,
            &proof,
        );

        let block_params = BlockParams {
            version: hex::decode("00000020").unwrap().try_into().unwrap(),
            previous_block_hash: hex::decode(
                "cf7e4d0d9ee9f0f12f7827c4518905d2ac9bcb7e033822689940e76300000000",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            timestamp: hex::decode("10405467").unwrap().try_into().unwrap(),
            n_bits: hex::decode("ffff001d").unwrap().try_into().unwrap(),
            nonce: hex::decode("07dc928f").unwrap().try_into().unwrap(),
        };

        let block_hash = calculate_block_hash(&block_params, root);

        assert_eq!(
            block_hash,
            <[u8; 32]>::try_from(
                hex::decode("ccbbcf2c854ac69d4d337a862cdf921daabe8896d3c990d02f21a3c900000000")
                    .unwrap()
            )
            .unwrap()
        );
    }
}
