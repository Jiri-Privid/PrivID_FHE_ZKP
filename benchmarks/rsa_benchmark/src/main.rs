use rand::rngs::ThreadRng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use std::time::Instant;

const ITERATIONS: usize = 400;

fn encrypt(public_key: &RsaPublicKey, rng: &mut ThreadRng, data: &[u8]) -> Vec<u8> {
    let padding = Oaep::new::<sha2::Sha256>();
    let enc_data = public_key
        .encrypt(rng, padding, &data[..])
        .expect("failed to encrypt");
    enc_data
}

fn decrypt(private_key: &RsaPrivateKey, enc_data: &Vec<u8>) -> Vec<u8> {
    // Decrypt
    let padding = Oaep::new::<sha2::Sha256>();
    let dec_data = private_key
        .decrypt(padding, &enc_data)
        .expect("failed to decrypt");
    dec_data
}

fn main() {
    let mut rng = rand::thread_rng();

    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let mut encrypted_values: Vec<Vec<u8>> = Vec::with_capacity(ITERATIONS);
    let mut decrypted_values: Vec<Vec<u8>> = Vec::with_capacity(ITERATIONS);

    let start = Instant::now();
    for i in 0..ITERATIONS {
        let data: Vec<u8> = i.to_be_bytes().into();
        let encrypted_data = encrypt(&public_key, &mut rng, &data);
        // Comment this println during benchmarks, as it is very slow.
        // println!("Size of encrypted number: {}", encrypted_data.len());
        encrypted_values.push(encrypted_data);
    }

    let elapsed = start.elapsed();
    let elapsed_ns = elapsed.as_nanos();
    let elapsed_each_encryption = elapsed_ns as f64 / ITERATIONS as f64;

    println!("Elapsed time: {:?}", elapsed);
    println!("Elapsed time (ns): {:?}ns", elapsed_ns);
    println!(
        "Time for each encryption(ns): {:?}ns",
        elapsed_each_encryption
    );

    let start = Instant::now();
    for i in &encrypted_values {
        decrypted_values.push(decrypt(&private_key, &i))
    }

    let elapsed = start.elapsed();
    let elapsed_ns = elapsed.as_nanos();
    let elapsed_each_decryption = elapsed_ns as f64 / ITERATIONS as f64;

    println!("Elapsed time: {:?}", elapsed);
    println!("Elapsed time (ns): {:?}ns", elapsed_ns);
    println!(
        "Time for each decryption(ns): {:?}ns",
        elapsed_each_decryption
    );
}
