use std::time::Instant;
use tfhe::integer::{gen_keys_radix, PublicKeyBig, RadixCiphertextBig, RadixClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

const NUMBLOCK: usize = 4;
const ITERATIONS_TFHE: u64 = 40;

fn encrypt_tfhe(public_key: &PublicKeyBig, value: u64) -> RadixCiphertextBig {
    public_key.encrypt_radix(value, NUMBLOCK)
}

fn compute_tfhe(
    server_key: &ServerKey,
    left: &mut RadixCiphertextBig,
    right: &mut RadixCiphertextBig,
) -> RadixCiphertextBig {
    server_key.smart_add(left, right)
}

fn compute_mul_tfhe(
    server_key: &ServerKey,
    left: &mut RadixCiphertextBig,
    right: &mut RadixCiphertextBig,
) -> RadixCiphertextBig {
    server_key.smart_mul(left, right)
}

fn compute_tfhe_scalar(server_key: &ServerKey, left: &mut RadixCiphertextBig, right: u64) {
    server_key.smart_scalar_add_assign(left, right);
}

fn compute_tfhe_mul_scalar(server_key: &ServerKey, left: &mut RadixCiphertextBig, right: u64) {
    server_key.smart_scalar_mul_assign(left, right)
}

fn decrypt_tfhe(client_key: &RadixClientKey, value: &RadixCiphertextBig) -> u64 {
    client_key.decrypt(value)
}

fn count_decryption(client_key: &RadixClientKey, encrypted_values: &Vec<RadixCiphertextBig>) {
    let mut decrypted_values: Vec<u64> = Vec::with_capacity(ITERATIONS_TFHE as usize);

    // Counting decryption time
    let start = Instant::now();
    for i in 0..encrypted_values.len() {
        decrypted_values.push(decrypt_tfhe(&client_key, &encrypted_values[i]));
    }

    let elapsed = start.elapsed();
    let elapsed_ns = elapsed.as_nanos();
    let elapsed_each_decryption = elapsed_ns as f64 / (ITERATIONS_TFHE - 1) as f64;

    println!("Elapsed time: {:?}", elapsed);
    println!("Elapsed time (ns): {:?}ns", elapsed_ns);
    println!(
        "Time for each decryption(ns): {:?}ns",
        elapsed_each_decryption
    );

    println!("\nResults after decryption:\n");
    for i in decrypted_values {
        print!("{i} ");
    }
    println!("\n");
}

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, NUMBLOCK);

    //We generate the public key from the secret client key:
    let public_key = PublicKeyBig::new(&client_key);
    let mut encrypted_values: Vec<RadixCiphertextBig> =
        Vec::with_capacity(ITERATIONS_TFHE as usize);
    let mut computed_values: Vec<RadixCiphertextBig> =
        Vec::with_capacity((ITERATIONS_TFHE) as usize);
    let mut computed_mul_values: Vec<RadixCiphertextBig> =
        Vec::with_capacity((ITERATIONS_TFHE) as usize);

    println!(
        "\n\nCounting the time to encrypt {} entries:\n",
        ITERATIONS_TFHE
    );
    // Counting encryption time
    let start = Instant::now();
    for i in 0..ITERATIONS_TFHE {
        if (i % 5) == 0 {
            println!("Encrypted {i} entries");
        }

        encrypted_values.push(encrypt_tfhe(&public_key, i));
    }

    let elapsed = start.elapsed();
    let elapsed_ns = elapsed.as_nanos();
    let elapsed_each_encryption = elapsed_ns as f64 / ITERATIONS_TFHE as f64;

    println!("Elapsed time: {:?}", elapsed);
    println!("Elapsed time (ns): {:?}ns", elapsed_ns);
    println!(
        "Time for each encryption(ns): {:?}ns",
        elapsed_each_encryption
    );

    let mut encrypted_values_right = encrypted_values.clone();

    // Counting sum time
    println!(
        "\n\nCounting the time to do sum operation in {} entries.\n",
        ITERATIONS_TFHE
    );
    let start = Instant::now();
    // For each entry in the Vec, sum the current element with the next.
    for i in 0..(ITERATIONS_TFHE) {
        let left = &mut encrypted_values[i as usize];
        let right = if i < ITERATIONS_TFHE - 1 {
            &mut encrypted_values_right[(i + 1) as usize]
        } else {
            &mut encrypted_values_right[0]
        };

        computed_values.push(compute_tfhe(&server_key, left, right));
    }

    let elapsed = start.elapsed();
    let elapsed_ns = elapsed.as_nanos();
    let elapsed_each_computation = elapsed_ns as f64 / (ITERATIONS_TFHE) as f64;

    println!("Elapsed time: {:?}", elapsed);
    println!("Elapsed time (ns): {:?}ns", elapsed_ns);
    println!(
        "Time for each computation(ns): {:?}ns",
        elapsed_each_computation
    );

    // Counting sum time
    println!(
        "\n\nCounting the time to do scalar operations in {} entries.\n",
        ITERATIONS_TFHE
    );

    let start = Instant::now();
    // For each entry in the Vec, sum the current element with the next.
    for i in 0..(ITERATIONS_TFHE - 1) {
        let left = &mut encrypted_values[i as usize];
        let right = i as u64;
        compute_tfhe_scalar(&server_key, left, right);
    }

    let elapsed = start.elapsed();
    let elapsed_ns = elapsed.as_nanos();
    let elapsed_each_computation = elapsed_ns as f64 / (ITERATIONS_TFHE - 1) as f64;

    println!("Elapsed time: {:?}", elapsed);
    println!("Elapsed time (ns): {:?}ns", elapsed_ns);
    println!(
        "Time for each scalar computation(ns): {:?}ns",
        elapsed_each_computation
    );

    // Counting multiplication time
    println!(
        "\n\nCounting the time to do multiplication operation in {} entries.\n",
        ITERATIONS_TFHE
    );
    let start = Instant::now();
    // For each entry in the Vec, multiply the current element with the next.
    for i in 0..(ITERATIONS_TFHE) {
        let left = &mut encrypted_values[i as usize];
        let right = if i < ITERATIONS_TFHE - 1 {
            &mut encrypted_values_right[(i + 1) as usize]
        } else {
            &mut encrypted_values_right[0]
        };

        computed_mul_values.push(compute_mul_tfhe(&server_key, left, right));
    }

    let elapsed = start.elapsed();
    let elapsed_ns = elapsed.as_nanos();
    let elapsed_each_computation = elapsed_ns as f64 / (ITERATIONS_TFHE) as f64;

    println!("Elapsed time: {:?}", elapsed);
    println!("Elapsed time (ns): {:?}ns", elapsed_ns);
    println!(
        "Time for each computation(ns): {:?}ns",
        elapsed_each_computation
    );

    // Counting mul time
    println!(
        "\n\nCounting the time to do scalar multiplication operations in {} entries.\n",
        ITERATIONS_TFHE
    );

    let start = Instant::now();
    // For each entry in the Vec, sum the current element with the next.
    for i in 0..(ITERATIONS_TFHE) {
        let left = &mut computed_mul_values[i as usize];
        let right = i as u64;
        compute_tfhe_mul_scalar(&server_key, left, right);
    }

    let elapsed = start.elapsed();
    let elapsed_ns = elapsed.as_nanos();
    let elapsed_each_computation = elapsed_ns as f64 / (ITERATIONS_TFHE) as f64;

    println!("Elapsed time: {:?}", elapsed);
    println!("Elapsed time (ns): {:?}ns", elapsed_ns);
    println!(
        "Time for each scalar multiplication(ns): {:?}ns",
        elapsed_each_computation
    );

    // Counting decryption times
    println!("\n\nCounting decryption for the first values\n");
    count_decryption(&client_key, &encrypted_values);

    println!("\n\nCounting decryption for computed values\n");
    count_decryption(&client_key, &computed_values);

    // Counting decryption times
    println!("\n\nCounting decryption for scalar computations\n");
    count_decryption(&client_key, &encrypted_values);
}
