#![allow(non_snake_case)]
extern crate curve25519_dalek;
extern crate libspartan;
extern crate merlin;

use libspartan::{Assignment, Instance, NIZKGens, NIZK};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

pub const NUMVARS: usize = 1024;
pub const NUMCONS: usize = 1024;
pub const NUMINPUTS: usize = 10;

// #[derive(Deserialize, Serialize)]
pub struct Proof {
    gens: NIZKGens,
    inst: Instance,
    inputs: Assignment,
    proof: NIZK,
}

impl Proof {
    pub fn new(gens: NIZKGens, inst: Instance, inputs: Assignment, proof: NIZK) -> Self {
        Self {
            gens,
            inst,
            inputs,
            proof,
        }
    }

    pub fn make_transcript<'a: 'static>(transcript: &'a [u8]) -> Transcript {
        Transcript::new(transcript)
    }

    pub fn verify(&self, verifier_transcript: &mut Transcript) -> Result<(), String> {
        let proof = &self.proof;
        println!("Size of proof is {}", std::mem::size_of_val(proof));
        let inst = &self.inst;
        println!("Size of instance is {}", std::mem::size_of_val(inst));
        let inputs = &self.inputs;
        println!("Size of inputs is {}", std::mem::size_of_val(inputs));
        let gens = &self.gens;
        println!("Size of gens is {}", std::mem::size_of_val(gens));

        match proof.verify(inst, inputs, verifier_transcript, gens) {
            Err(err) => {
                let error = err.to_string();
                Err(error)
            }
            Ok(()) => Ok(()),
        }
    }
}

pub struct Circuit {
    gens: NIZKGens,
    inst: Instance,
    vars: Assignment,
    inputs: Assignment,
    prover_transcript: Transcript,
}

impl Circuit {
    pub fn new<'a: 'static>(label: &'a [u8]) -> Self {
        // produce public parameters
        let gens = NIZKGens::new(NUMCONS, NUMVARS, NUMINPUTS);

        // ask the library to produce a synthentic R1CS instance
        let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(NUMCONS, NUMVARS, NUMINPUTS);

        // produce a proof of satisfiability
        let prover_transcript = Transcript::new(label);

        Self {
            gens,
            inst,
            vars,
            inputs,
            prover_transcript,
        }
    }

    pub fn prove<'a: 'static>(self) -> Proof {
        let inst = self.inst;
        let vars = self.vars.clone();
        let inputs = self.inputs;
        let gens = self.gens;
        let mut prover_transcript = self.prover_transcript.clone();
        let proof = NIZK::prove(&inst, vars, &inputs, &gens, &mut prover_transcript);
        Proof::new(gens, inst, inputs, proof)
    }
}

pub fn example() {
    let circuit: Circuit = Circuit::new("Testing example".as_bytes());
    let proof: Proof = circuit.prove();

    let mut transcript = Proof::make_transcript("Testing example".as_bytes());
    proof.verify(&mut transcript).unwrap();
    println!("Example NIZK proof verification successful!");
}
