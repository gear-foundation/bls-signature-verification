use ark_bls12_381::{G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::{Group};

use ark_serialize::CanonicalSerialize;
use ark_std::{
    ops::{Mul},
    UniformRand,
};
use gclient::{EventListener, EventProcessor, GearApi, Result};
use gstd::prelude::*;
use bls381_verification::*;
type ScalarField = <G2 as Group>::ScalarField;
pub const PATH: &str = "./target/wasm32-unknown-unknown/release/bls381_verification.opt.wasm";

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

