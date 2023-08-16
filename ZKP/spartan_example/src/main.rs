#![allow(non_snake_case)]
extern crate curve25519_dalek;
extern crate libspartan;
extern crate merlin;
use curve25519_dalek::scalar::Scalar;
use libspartan::{InputsAssignment, Instance, NIZKGens, SNARKGens, VarsAssignment, NIZK, SNARK};
use merlin::Transcript;
use rand::rngs::OsRng;

use spartan_example::example;

fn snark_proof() {
    // specify the size of an R1CS instance
    let num_vars = 1024;
    let num_cons = 1024;
    let num_inputs = 10;
    let num_non_zero_entries = 1024;

    // produce public parameters
    let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_non_zero_entries);

    // ask the library to produce a synthentic R1CS instance
    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    // create a commitment to the R1CS instance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"snark_example");
    let proof = SNARK::prove(
        &inst,
        &comm,
        &decomm,
        vars,
        &inputs,
        &gens,
        &mut prover_transcript,
    );

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"snark_example");
    assert!(proof
        .verify(&comm, &inputs, &mut verifier_transcript, &gens)
        .is_ok());
    println!("SNARK proof verification successful!");
}

fn nizk_proof() {
    // specify the size of an R1CS instance
    let num_vars = 1024;
    let num_cons = 1024;
    let num_inputs = 10;

    // produce public parameters
    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

    // ask the library to produce a synthentic R1CS instance
    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"nizk_example");
    let proof = NIZK::prove(&inst, vars, &inputs, &gens, &mut prover_transcript);

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"nizk_example");
    assert!(proof
        .verify(&inst, &inputs, &mut verifier_transcript, &gens)
        .is_ok());
    println!("NIZK proof verification successful!");
}

fn r1cs_proof() {
    // produce a tiny instance
    let (
        num_cons,
        num_vars,
        num_inputs,
        num_non_zero_entries,
        inst,
        assignment_vars,
        assignment_inputs,
    ) = produce_tiny_r1cs();

    // produce public parameters
    let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_non_zero_entries);

    // create a commitment to the R1CS instance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"snark_example");
    let proof = SNARK::prove(
        &inst,
        &comm,
        &decomm,
        assignment_vars,
        &assignment_inputs,
        &gens,
        &mut prover_transcript,
    );

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"snark_example");
    assert!(proof
        .verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens)
        .is_ok());
    println!("r1cs proof verification successful!");
}

fn produce_tiny_r1cs() -> (
    usize,
    usize,
    usize,
    usize,
    Instance,
    VarsAssignment,
    InputsAssignment,
) {
    // We will use the following example, but one could construct any R1CS instance.
    // Our R1CS instance is three constraints over five variables and two public inputs
    // (Z0 + Z1) * I0 - Z2 = 0
    // (Z0 + I1) * Z2 - Z3 = 0
    // Z4 * 1 - 0 = 0

    // parameters of the R1CS instance rounded to the nearest power of two
    let num_cons = 4;
    let num_vars = 5;
    let num_inputs = 2;
    let num_non_zero_entries = 5;

    // We will encode the above constraints into three matrices, where
    // the coefficients in the matrix are in the little-endian byte order
    let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

    // The constraint system is defined over a finite field, which in our case is
    // the scalar field of ristreeto255/curve25519 i.e., p =  2^{252}+27742317777372353535851937790883648493
    // To construct these matrices, we will use `curve25519-dalek` but one can use any other method.

    // a variable that holds a byte representation of 1
    let one = Scalar::one().to_bytes();

    // R1CS is a set of three sparse matrices A B C, where is a row for every
    // constraint and a column for every entry in z = (vars, 1, inputs)
    // An R1CS instance is satisfiable iff:
    // Az \circ Bz = Cz, where z = (vars, 1, inputs)

    // constraint 0 entries in (A,B,C)
    // constraint 0 is (Z0 + Z1) * I0 - Z2 = 0.
    // We set 1 in matrix A for columns that correspond to Z0 and Z1
    // We set 1 in matrix B for column that corresponds to I0
    // We set 1 in matrix C for column that corresponds to Z2
    A.push((0, 0, one));
    A.push((0, 1, one));
    B.push((0, num_vars + 1, one));
    C.push((0, 2, one));

    // constraint 1 entries in (A,B,C)
    A.push((1, 0, one));
    A.push((1, num_vars + 2, one));
    B.push((1, 2, one));
    C.push((1, 3, one));

    // constraint 3 entries in (A,B,C)
    A.push((2, 4, one));
    B.push((2, num_vars, one));

    let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();

    // compute a satisfying assignment
    let mut csprng: OsRng = OsRng;
    let i0 = Scalar::random(&mut csprng);
    let i1 = Scalar::random(&mut csprng);
    let z0 = Scalar::random(&mut csprng);
    let z1 = Scalar::random(&mut csprng);
    let z2 = (z0 + z1) * i0; // constraint 0
    let z3 = (z0 + i1) * z2; // constraint 1
    let z4 = Scalar::zero(); //constraint 2

    // create a VarsAssignment
    let mut vars = vec![Scalar::zero().to_bytes(); num_vars];
    vars[0] = z0.to_bytes();
    vars[1] = z1.to_bytes();
    vars[2] = z2.to_bytes();
    vars[3] = z3.to_bytes();
    vars[4] = z4.to_bytes();
    let assignment_vars = VarsAssignment::new(&vars).unwrap();

    // create an InputsAssignment
    let mut inputs = vec![Scalar::zero().to_bytes(); num_inputs];
    inputs[0] = i0.to_bytes();
    inputs[1] = i1.to_bytes();
    let assignment_inputs = InputsAssignment::new(&inputs).unwrap();

    // check if the instance we created is satisfiable
    let res = inst.is_sat(&assignment_vars, &assignment_inputs);
    assert!(res.unwrap());

    (
        num_cons,
        num_vars,
        num_inputs,
        num_non_zero_entries,
        inst,
        assignment_vars,
        assignment_inputs,
    )
}

/// This needs to be run with
/// cargo +nightly run --release
///
/// It can be installed with
/// rustup toolchain install nightly
fn main() {
    snark_proof();
    nizk_proof();
    r1cs_proof();
    example();
}
