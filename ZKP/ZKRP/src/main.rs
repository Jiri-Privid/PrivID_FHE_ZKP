extern crate rand;
use rand::thread_rng;

extern crate curve25519_dalek;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};

extern crate merlin;
use merlin::Transcript;

extern crate tari_bulletproofs;
use serde::{Deserialize, Serialize};
use tari_bulletproofs::{BulletproofGens, PedersenGens, ProofError, RangeProof};

#[derive(Deserialize, Serialize)]
pub struct Proof {
    committed_value: CompressedRistretto,
    proof: RangeProof,
    label: &'static str,
    n: usize,
}

impl Proof {
    pub fn under_age_18(age: u64, label: &'static str) -> Self {
        let n = 8;
        let verify_age: u64 = age + 238;

        // Generators for Pedersen commitments. These can be selected independently of the Bulletproofs generators.
        let pc_gens = PedersenGens::default();

        // Generators for Bulletproofs, valid for proofs up to bitsize 64
        // and aggregation size up to 1.
        let bp_gens = BulletproofGens::new(64, 1);

        // The API takes a blinding factor for the commitment.
        let blinding = Scalar::random(&mut thread_rng());

        // The proof can be chained to an existing transcript.
        // Here we create a transcript with a doctest domain separator.
        let mut prover_transcript = Transcript::new(label.as_bytes());

        // Create a 32-bit rangeproof.
        let (proof, committed_value) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            verify_age,
            &blinding,
            n,
        )
        .expect("A real program would handle errors");

        Proof {
            committed_value,
            proof,
            label,
            n,
        }
    }

    fn verify(&self) -> Result<(), ProofError> {
        let n = self.n;
        let label = self.label.as_bytes();
        // Generators for Pedersen commitments. These can be selected independently of the Bulletproofs generators.
        let pc_gens = PedersenGens::default();

        // Generators for Bulletproofs, valid for proofs up to bitsize 64
        // and aggregation size up to 1.
        let bp_gens = BulletproofGens::new(64, 1);
        let mut verifier_transcript = Transcript::new(label);
        self.proof.verify_single(
            &bp_gens,
            &pc_gens,
            &mut verifier_transcript,
            &self.committed_value,
            n,
        )
    }
}

fn main() {
    for age in 0..100 {
        let proof = Proof::under_age_18(age, "doctest example");
        let result = proof.verify();
        if age < 18 {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
        println!("Age {age} verification successful");
    }
}
