use ark_bls12_381::{Bls12_381, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};

use ark_groth16::{Groth16, PreparedVerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::{
    ops::{Mul, Neg},
    UniformRand,
};
use gclient::{EventListener, EventProcessor, GearApi, Result};
use gstd::prelude::*;
use test_bn254::*;
type ScalarField = <G2 as Group>::ScalarField;
pub const PATH: &str = "./target/wasm32-unknown-unknown/release/test_bn254.opt.wasm";

type ArkScale<T> = ark_scale::ArkScale<T, { ark_scale::HOST_CALL }>;

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
    for _ in 0..10 {
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
    let client = GearApi::dev().await?.with("//Alice")?;
    let mut listener = client.subscribe().await?;

    let mut rng = ark_std::test_rng();

    let (priv_keys, pub_keys) = generate_key_pairs(10);

    let program_id = upload_program(&client, &mut listener, PATH, InitMessage { pub_keys }).await?;

    let message: G1Affine = G1::rand(&mut rng).into();

    // sign
    let mut signatures = Vec::new();
    let signing_keys_ids: Vec<u8> = vec![1, 3, 4, 5, 6, 8];
    for i in signing_keys_ids.clone() {
        let signature: G1Affine = message.mul(priv_keys[i as usize]).into();
        let mut sig_bytes = Vec::new();
        signature.serialize_uncompressed(&mut sig_bytes).unwrap();
        signatures.push(sig_bytes);
    }

    let message: ArkScale<Vec<G1Affine>> = vec![message].into();
    let message_bytes = message.encode();

    let payload = HandleMessage::VerifyBlsSignature {
        signing_keys_ids,
        signatures,
        message: message_bytes,
    };
    let gas_limit = client
        .calculate_handle_gas(None, program_id.into(), payload.encode(), 0, true)
        .await?
        .min_limit;
    println!("gas_limit {:?}", gas_limit);

    let (message_id, _) = client
        .send_message(program_id.into(), payload, gas_limit, 0)
        .await?;

    assert!(listener
        .message_processed(message_id.into())
        .await?
        .succeed());

    Ok(())
}

// This test checks the verification process to ensure it correctly identifies and rejects an incorrect signature.
#[tokio::test]
async fn test_signature_verification_failure_incorrect_signature() -> Result<()> {
    let client = GearApi::dev().await?.with("//Alice")?;
    let mut listener = client.subscribe().await?;

    let mut rng = ark_std::test_rng();

    let (priv_keys, pub_keys) = generate_key_pairs(10);

    let program_id = upload_program(&client, &mut listener, PATH, InitMessage { pub_keys }).await?;

    let message: G1Affine = G1::rand(&mut rng).into();

    // sign
    let mut signatures = Vec::new();
    let signing_keys_ids: Vec<u8> = vec![1, 3, 4, 5, 6, 8];
    // one signature is incorrect
    for i in signing_keys_ids.clone() {
        let signature: G1Affine = message.mul(priv_keys[i as usize]).into();
        let mut sig_bytes = Vec::new();
        signature.serialize_uncompressed(&mut sig_bytes).unwrap();
        signatures.push(sig_bytes);
    }

    // one signature is incorrect
    let signature: G1Affine = G1::rand(&mut rng).into();
    let mut sig_bytes = Vec::new();
    signature.serialize_uncompressed(&mut sig_bytes).unwrap();
    signatures[0] = sig_bytes;

    let message: ArkScale<Vec<G1Affine>> = vec![message].into();
    let message_bytes = message.encode();

    let payload = HandleMessage::VerifyBlsSignature {
        signing_keys_ids,
        signatures,
        message: message_bytes,
    };

    let (message_id, _) = client
        .send_message(program_id.into(), payload, 35_000_000_000, 0)
        .await?;

    assert!(listener
        .message_processed(message_id.into())
        .await?
        .failed());

    Ok(())
}

// This test verifies that the signature verification process fails
// when the message being verified is not the same as the message that was originally signed.
#[tokio::test]
async fn test_signature_verification_failure_message_mismatch() -> Result<()> {
    let client = GearApi::dev().await?.with("//Alice")?;
    let mut listener = client.subscribe().await?;

    let mut rng = ark_std::test_rng();

    let (priv_keys, pub_keys) = generate_key_pairs(10);

    let program_id = upload_program(&client, &mut listener, PATH, InitMessage { pub_keys }).await?;

    let message: G1Affine = G1::rand(&mut rng).into();

    // sign
    let mut signatures = Vec::new();
    let signing_keys_ids: Vec<u8> = vec![1, 3, 4, 5, 6, 8];
    for i in signing_keys_ids.clone() {
        let signature: G1Affine = message.mul(priv_keys[i as usize]).into();
        let mut sig_bytes = Vec::new();
        signature.serialize_uncompressed(&mut sig_bytes).unwrap();
        signatures.push(sig_bytes);
    }
    let wrong_message: G1Affine = G1::rand(&mut rng).into();
    let message: ArkScale<Vec<G1Affine>> = vec![wrong_message].into();
    let message_bytes = message.encode();

    let payload = HandleMessage::VerifyBlsSignature {
        signing_keys_ids,
        signatures,
        message: message_bytes,
    };

    let (message_id, _) = client
        .send_message(program_id.into(), payload, 35_000_000_000, 0)
        .await?;

    assert!(listener
        .message_processed(message_id.into())
        .await?
        .failed());

    Ok(())
}

// This test ensures that the verification process identifies
// when not all designated addresses have signed the message, leading to a failed verification.
#[tokio::test]
async fn test_signature_verification_failure_incomplete_signatures() -> Result<()> {
    let client = GearApi::dev().await?.with("//Alice")?;
    let mut listener = client.subscribe().await?;

    let mut rng = ark_std::test_rng();
    let generator: G2 = G2::generator();

    let (priv_keys, pub_keys) = generate_key_pairs(10);

    let program_id = upload_program(&client, &mut listener, PATH, InitMessage { pub_keys }).await?;

    let message: G1Affine = G1::rand(&mut rng).into();

    // sign
    let mut signatures = Vec::new();
    let signing_keys_ids: Vec<u8> = vec![1, 3, 4, 5, 6, 8];
    for i in signing_keys_ids.clone() {
        let signature: G1Affine = message.mul(priv_keys[i as usize]).into();
        let mut sig_bytes = Vec::new();
        signature.serialize_uncompressed(&mut sig_bytes).unwrap();
        signatures.push(sig_bytes);
    }
    signatures.pop();

    let message: ArkScale<Vec<G1Affine>> = vec![message].into();
    let message_bytes = message.encode();

    let payload = HandleMessage::VerifyBlsSignature {
        signing_keys_ids,
        signatures,
        message: message_bytes,
    };

    let (message_id, _) = client
        .send_message(program_id.into(), payload, 35_000_000_000, 0)
        .await?;

    assert!(listener
        .message_processed(message_id.into())
        .await?
        .failed());

    Ok(())
}

// #[tokio::test]
// async fn zk_node() -> Result<()> {
//     let cfg = CircomConfig::<Bls12_381>::new("multiply.wasm", "multiply.r1cs").unwrap();

//     let mut builder = CircomBuilder::new(cfg);
//     builder.push_input("a", 7);
//     builder.push_input("b", 8);

//     let circom = builder.setup();

//     let mut rng = rand::thread_rng();
//     let params =
//         Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circom, &mut rng).unwrap();

//     let circom = builder.build().unwrap();

//     // There's only one public input, namely the hash digest.
//     let inputs = circom.get_public_inputs().unwrap();

//     // Generate the proof
//     let proof = Groth16::<Bls12_381>::prove(&params, circom, &mut rng).unwrap();

//     // Check that the proof is valid
//     let vk = Groth16::<Bls12_381>::process_vk(&params.vk).unwrap();
//     let pvk: PreparedVerifyingKey<Bls12_381> = vk.into();

//     let mut alpha_g1_beta_g2 = Vec::new();
//     pvk.alpha_g1_beta_g2
//         .serialize_uncompressed(&mut alpha_g1_beta_g2)
//         .unwrap();

//     let gamma_g2_neg_pc_g2 = pvk.vk.gamma_g2.into_group().neg().into_affine();
//     let delta_g2_neg_pc_g2 = pvk.vk.delta_g2.into_group().neg().into_affine();
//     let mut gamma_g2_neg_pc = Vec::new();
//     gamma_g2_neg_pc_g2
//         .serialize_uncompressed(&mut gamma_g2_neg_pc)
//         .unwrap();

//     let mut delta_g2_neg_pc = Vec::new();
//     delta_g2_neg_pc_g2
//         .serialize_uncompressed(&mut delta_g2_neg_pc)
//         .unwrap();

//     let mut a = Vec::new();
//     proof.a.serialize_uncompressed(&mut a).unwrap();

//     let mut b = Vec::new();
//     proof.b.serialize_uncompressed(&mut b).unwrap();

//     let mut c = Vec::new();
//     proof.c.serialize_uncompressed(&mut c).unwrap();

//     let mut prepared_inputs_bytes = Vec::new();
//     let prepared_inputs = Groth16::<Bls12_381>::prepare_inputs(&pvk, &inputs).unwrap();

//     prepared_inputs
//         .serialize_uncompressed(&mut prepared_inputs_bytes)
//         .unwrap();

//     let client = GearApi::dev().await?.with("//Alice")?;
//     let mut listener = client.subscribe().await?;

//     println!("{:?}", prepared_inputs);

//     let program_id = upload_program(&client, &mut listener, PATH, String::from("")).await?;

//     // type ScalarField = <G2 as Group>::ScalarField;

//     let payload = HandleMessage::ZKVerify {
//         vk: VerifyingKeyBytes {
//             alpha_g1_beta_g2: alpha_g1_beta_g2.clone(),
//             gamma_g2_neg_pc: gamma_g2_neg_pc.clone(),
//             delta_g2_neg_pc: delta_g2_neg_pc.clone(),
//         },
//         proof: ProofBytes {
//             a: a.clone(),
//             b: b.clone(),
//             c: c.clone(),
//         },
//         prepared_inputs_bytes: prepared_inputs_bytes.clone(),
//     };
//     let gas_limit = client
//         .calculate_handle_gas(None, program_id.into(), payload.encode(), 0, true)
//         .await?
//         .min_limit;
//     println!("gas_limit {:?}", gas_limit);

//     let (message_id, _) = client
//         .send_message(program_id.into(), payload, gas_limit, 0)
//         .await?;

//     assert!(listener
//         .message_processed(message_id.into())
//         .await?
//         .succeed());

//     // let alpha_g1_beta_g2 = <ArkScale<<Bls12_381 as Pairing>::TargetField> as Decode>::decode(
//     //     &mut alpha_g1_beta_g2.as_slice(),
//     // )
//     // .unwrap();

//     // let gamma_g2_neg_pc = <ArkScale<<Bls12_381 as Pairing>::G2Affine> as Decode>::decode(
//     //     &mut gamma_g2_neg_pc.as_slice(),
//     // )
//     // .unwrap();

//     // let delta_g2_neg_pc = <ArkScale<<Bls12_381 as Pairing>::G2Affine> as Decode>::decode(
//     //     &mut delta_g2_neg_pc.as_slice(),
//     // )
//     // .unwrap();

//     // let a = <ArkScale<<Bls12_381 as Pairing>::G1Affine> as Decode>::decode(&mut a.as_slice())
//     //     .unwrap();

//     // let b = <ArkScale<<Bls12_381 as Pairing>::G2Affine> as Decode>::decode(&mut b.as_slice())
//     //     .unwrap();

//     // let c = <ArkScale<<Bls12_381 as Pairing>::G1Affine> as Decode>::decode(&mut c.as_slice())
//     //     .unwrap();

//     // let prepared_inputs = <ArkScale<<Bls12_381 as Pairing>::G1Affine> as Decode>::decode(
//     //     &mut prepared_inputs_bytes.as_slice(),
//     // )
//     // .unwrap();

//     let miller_out = Bls12_381::multi_miller_loop(
//         [proof.a, prepared_inputs.into(), proof.c],
//         [proof.b.into(), pvk.gamma_g2_neg_pc, pvk.delta_g2_neg_pc],
//     );

//     let mut miller_out_bytes = Vec::new();
//     miller_out
//         .0
//         .serialize_uncompressed(&mut miller_out_bytes)
//         .unwrap();
//     println!(" miller out {:?}", miller_out_bytes.encode());

//     let exp = Bls12_381::final_exponentiation(miller_out).unwrap();

//     println!("exp {:#?}", exp.0);
//     println!("alpha_g1_beta_g2 {:#?}", pvk.alpha_g1_beta_g2);

//     assert_eq!(exp.0, pvk.alpha_g1_beta_g2);

//     let a: ArkScale<Vec<G1Affine>> = vec![proof.a, prepared_inputs.into(), proof.c].into();

//     let gamma_g2_neg_pc = pvk.vk.gamma_g2.into_group().neg().into_affine();
//     let delta_g2_neg_pc = pvk.vk.delta_g2.into_group().neg().into_affine();
//     let b: ArkScale<Vec<G2Affine>> = vec![proof.b, gamma_g2_neg_pc, delta_g2_neg_pc].into();
//     println!("a {:#?}", a.encode());
//     println!("b {:#?}", b.encode());

//     Ok(())
// }
