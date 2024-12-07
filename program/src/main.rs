//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use btc_lib::{btc::BitMix, PublicValuesStruct};

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let verifier = sp1_zkvm::io::read::<BitMix>();

    // Compute the n'th fibonacci number using a function from the workspace lib crate.
    let (verified, block_hashes, pub_a_x, pub_a_y, cipher_text) = verifier.verify();

    assert!(verified);

    // Encode the public values of the program.
    let block_hashes_array: [alloy_sol_types::private::FixedBytes<32>; 1] =
        [alloy_sol_types::private::FixedBytes::from(block_hashes[0])];
    let cipher = alloy_sol_types::private::Bytes::from(cipher_text);

    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        block_hashes: block_hashes_array,
        pub_a_x: alloy_sol_types::private::FixedBytes(pub_a_x),
        pub_a_y: alloy_sol_types::private::FixedBytes(pub_a_y),
        cipher,
    });
    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
