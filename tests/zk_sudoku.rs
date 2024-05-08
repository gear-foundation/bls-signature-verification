use ark_bls12_381::Bls12_381;
use ark_bls12_381::{G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::Group;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_groth16::Groth16;
use ark_groth16::PreparedVerifyingKey;
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean, EqGadget},
    uint8::UInt8,
};
use ark_relations::r1cs::ConstraintSystem;
use ark_relations::{
    lc, ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};
use ark_snark::CircuitSpecificSetupSNARK;
mod alloc;
use alloc::{Solution, Sudoku};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::ops::{Mul, Neg};
use ark_std::rand::{Rng, RngCore, SeedableRng};
use ark_std::test_rng;
use ark_std::UniformRand;
use bls381_verification::*;
use gclient::{EventListener, EventProcessor, GearApi, Result};
use gstd::prelude::*;
type ScalarField = <G2 as Group>::ScalarField;
pub const PATH: &str = "./target/wasm32-unknown-unknown/release/zk_groth_verification.opt.wasm";

mod cmp;
use cmp::CmpGadget;

type ArkScale<T> = ark_scale::ArkScale<T, { ark_scale::HOST_CALL }>;

struct Puzzle<const N: usize> {
    sudoku: Option<[[u8; N]; N]>,
    solution: Option<[[u8; N]; N]>,
}

fn check_rows<const N: usize, ConstraintF: Field>(
    solution: &Solution<N, ConstraintF>,
) -> Result<(), SynthesisError> {
    for row in &solution.0 {
        for (j, cell) in row.iter().enumerate() {
            for prev in &row[0..j] {
                cell.is_neq(&prev)?.enforce_equal(&Boolean::TRUE)?;
            }
        }
    }
    Ok(())
}

fn check_cols<const N: usize, ConstraintF: Field>(
    solution: &Solution<N, ConstraintF>,
) -> Result<(), SynthesisError> {
    let mut transpose: Vec<Vec<UInt8<ConstraintF>>> = Vec::with_capacity(N * N);
    for i in 0..9 {
        let col = &solution
            .0
            .clone()
            .into_iter()
            .map(|s| s.into_iter().nth(i).unwrap())
            .collect::<Vec<UInt8<ConstraintF>>>();
        transpose.push(col.to_vec());
    }
    for row in transpose {
        for (j, cell) in row.iter().enumerate() {
            for prev in &row[0..j] {
                cell.is_neq(&prev)?.enforce_equal(&Boolean::TRUE)?;
            }
        }
    }
    Ok(())
}

fn check_3By3<const N: usize, ConstraintF: Field>(
    solution: &Solution<N, ConstraintF>,
) -> Result<(), SynthesisError> {
    let mut flat: Vec<UInt8<ConstraintF>> = Vec::with_capacity(N * N);
    for i in 0..3 {
        for j in 0..3 {
            flat.push(solution.0[i][j].clone());
        }
    }
    for (j, cell) in flat.iter().enumerate() {
        for prev in &flat[0..j] {
            cell.is_neq(&prev)?.enforce_equal(&Boolean::TRUE)?;
        }
    }
    Ok(())
}

impl<const N: usize, F: Field> ConstraintSynthesizer<F> for Puzzle<N> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let mut sudoku = self.sudoku;
        let mut solution = self.solution;

        let mut sudoku_var = Sudoku::new_witness(cs.clone(), || {
            sudoku.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let mut solution_var = Solution::new_witness(cs.clone(), || {
            solution.ok_or(SynthesisError::AssignmentMissing)
        })?;

        check_sudoku_solution(&sudoku_var, &solution_var)?;
        check_rows(&solution_var)?;
        check_cols(&solution_var)?;
        check_3By3(&solution_var)?;
        Ok(())
    }
}

fn check_sudoku_solution<const N: usize, ConstraintF: Field>(
    sudoku: &Sudoku<N, ConstraintF>,
    solution: &Solution<N, ConstraintF>,
) -> Result<(), SynthesisError> {
    for i in 0..9 {
        for j in 0..9 {
            let a = &sudoku.0[i][j];
            let b = &solution.0[i][j];
            (a.is_eq(b)?.or(&a.is_eq(&UInt8::constant(0))?)?).enforce_equal(&Boolean::TRUE)?;

            b.is_leq(&UInt8::constant(N as u8))?
                .and(&b.is_geq(&UInt8::constant(1))?)?
                .enforce_equal(&Boolean::TRUE)?;
        }
    }
    Ok(())
}

fn check_helper<const N: usize, ConstraintF: Field>(
    sudoku: &[[u8; N]; N],
    solution: &[[u8; N]; N],
) {
    let cs = ConstraintSystem::<ConstraintF>::new_ref();
    let sudoku_var = Sudoku::new_input(cs.clone(), || Ok(sudoku)).unwrap();
    let solution_var = Solution::new_witness(cs.clone(), || Ok(solution)).unwrap();
    check_sudoku_solution(&sudoku_var, &solution_var).unwrap();
    check_rows(&solution_var).unwrap();
    check_cols(&solution_var).unwrap();
    check_3By3(&solution_var).unwrap();
    assert!(cs.is_satisfied().unwrap());
}

pub async fn common_upload_program(
    client: &GearApi,
    code: Vec<u8>,
    payload: impl Encode,
) -> Result<([u8; 32], [u8; 32])> {
    let encoded_payload = payload.encode();
    let gas_limit = client
        .calculate_upload_gas(None, code.clone(), encoded_payload, 0, true)
        .await?
        .min_limit;
    println!(" init gas {:?}", gas_limit);
    let (message_id, program_id, _) = client
        .upload_program(
            code,
            gclient::now_micros().to_le_bytes(),
            payload,
            gas_limit,
            0,
        )
        .await?;

    Ok((message_id.into(), program_id.into()))
}

pub async fn upload_program(
    client: &GearApi,
    listener: &mut EventListener,
    path: &str,
    payload: impl Encode,
) -> Result<[u8; 32]> {
    let (message_id, program_id) =
        common_upload_program(client, gclient::code_from_os(path)?, payload).await?;

    assert!(listener
        .message_processed(message_id.into())
        .await?
        .succeed());

    Ok(program_id)
}

fn generate_key_pairs(number_of_keys: u8) -> (Vec<ScalarField>, Vec<Vec<u8>>) {
    let mut rng = ark_std::test_rng();
    let generator: G2 = G2::generator();

    let mut priv_keys = Vec::new();
    let mut pub_keys = Vec::new();

    // Loop to generate 10 pairs of private and public keys
    for _ in 0..number_of_keys {
        // Generate a random private key using a uniform distribution
        let priv_key: ScalarField = UniformRand::rand(&mut rng);

        // Calculate the corresponding public key by multiplying the generator point with the private key
        let pub_key: G2Affine = generator.mul(priv_key).into();

        // Initialize a vector to store the public key bytes
        let mut pub_key_bytes = Vec::new();

        // Serialize the public key into uncompressed form and store it in the vector
        pub_key.serialize_uncompressed(&mut pub_key_bytes).unwrap();

        // Append the serialized public key bytes to the public keys collection
        pub_keys.push(pub_key_bytes);

        // Append the private key to the private keys collection
        priv_keys.push(priv_key);
    }
    (priv_keys, pub_keys)
}

// #[ignore]
#[tokio::test]
async fn test_signature_verification_success() -> Result<()> {
    println!("ZERO KNOWLEDGE SUDOKU R1CS");
    use ark_bls12_381::Fq as F;
    let sudoku = [
        [0, 0, 0, 2, 6, 0, 7, 0, 1],
        [6, 8, 0, 0, 7, 0, 0, 9, 0],
        [1, 9, 0, 0, 0, 4, 5, 0, 0],
        [8, 2, 0, 1, 0, 0, 0, 4, 0],
        [0, 0, 4, 6, 0, 2, 9, 0, 0],
        [0, 5, 0, 0, 0, 3, 0, 2, 8],
        [0, 0, 9, 3, 0, 0, 0, 7, 4],
        [0, 4, 0, 0, 5, 0, 0, 3, 6],
        [7, 0, 3, 0, 1, 8, 0, 0, 0],
    ];
    let solution = [
        [4, 3, 5, 2, 6, 9, 7, 8, 1],
        [6, 8, 2, 5, 7, 1, 4, 9, 3],
        [1, 9, 7, 8, 3, 4, 5, 6, 2],
        [8, 2, 6, 1, 9, 5, 3, 4, 7],
        [3, 7, 4, 6, 8, 2, 9, 1, 5],
        [9, 5, 1, 7, 4, 3, 6, 2, 8],
        [5, 1, 9, 3, 2, 6, 8, 7, 4],
        [2, 4, 8, 9, 5, 7, 1, 3, 6],
        [7, 6, 3, 4, 1, 8, 2, 5, 9],
    ];

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    println!("SET UP CIRCUIT AND GENERATE PK AND VK");
    let (pk, vk) = {
        let c = Puzzle::<9> {
            sudoku: None,
            solution: None,
        };
        Groth16::<Bls12_381>::setup(c, &mut rng).unwrap()
    };

    println!("GENERATE PROOF");
    let example = Puzzle::<9> {
        sudoku: Some(sudoku),
        solution: Some(solution),
    };

    let proof = Groth16::<Bls12_381>::prove(&pk, example, &mut rng).unwrap();

    let pvk: PreparedVerifyingKey<Bls12_381> = vk.into();

    let mut alpha_g1_beta_g2 = Vec::new();
    pvk.alpha_g1_beta_g2
        .serialize_uncompressed(&mut alpha_g1_beta_g2)
        .unwrap();

    let gamma_g2_neg_pc_g2 = pvk.vk.gamma_g2.into_group().neg().into_affine();
    let delta_g2_neg_pc_g2 = pvk.vk.delta_g2.into_group().neg().into_affine();

    let mut gamma_g2_neg_pc = Vec::new();
    gamma_g2_neg_pc_g2
        .serialize_uncompressed(&mut gamma_g2_neg_pc)
        .unwrap();

    let mut delta_g2_neg_pc = Vec::new();
    delta_g2_neg_pc_g2
        .serialize_uncompressed(&mut delta_g2_neg_pc)
        .unwrap();

    let mut a = Vec::new();
    proof.a.serialize_uncompressed(&mut a).unwrap();

    let mut b = Vec::new();
    proof.b.serialize_uncompressed(&mut b).unwrap();

    let mut c = Vec::new();
    proof.c.serialize_uncompressed(&mut c).unwrap();

    let prepared_inputs = Groth16::<Bls12_381>::prepare_inputs(&pvk, &[]).unwrap();
    let mut prepared_inputs_bytes = Vec::new();
    prepared_inputs
        .serialize_uncompressed(&mut prepared_inputs_bytes)
        .unwrap();

    let client = GearApi::dev().await?.with("//Alice")?;
    let mut listener = client.subscribe().await?;

    // let mut rng = ark_std::test_rng();

    // let (priv_keys, pub_keys) = generate_key_pairs(10);

    // let program_id = upload_program(&client, &mut listener, PATH, InitMessage { pub_keys }).await?;

    // let message: G1Affine = G1::rand(&mut rng).into();

    // // sign
    // let mut signatures = Vec::new();
    // let signing_keys_ids: Vec<u8> = vec![1, 3, 4, 5, 6, 8];
    // for i in signing_keys_ids.clone() {
    //     let signature: G1Affine = message.mul(priv_keys[i as usize]).into();
    //     let mut sig_bytes = Vec::new();
    //     signature.serialize_uncompressed(&mut sig_bytes).unwrap();
    //     signatures.push(sig_bytes);
    // }

    // let message: ArkScale<Vec<G1Affine>> = vec![message].into();
    // let message_bytes = message.encode();

    // let payload = HandleMessage::VerifyBlsSignature {
    //     signing_keys_ids,
    //     signatures,
    //     message: message_bytes,
    // };
    // let gas_limit = client
    //     .calculate_handle_gas(None, program_id.into(), payload.encode(), 0, true)
    //     .await?
    //     .min_limit;
    // println!("gas_limit {:?}", gas_limit);

    // let (message_id, _) = client
    //     .send_message(program_id.into(), payload, gas_limit, 0)
    //     .await?;

    // assert!(listener
    //     .message_processed(message_id.into())
    //     .await?
    //     .succeed());

    Ok(())
}
