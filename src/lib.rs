#![no_std]

use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use gbuiltin_bls381::ark_serialize::CanonicalDeserialize;
use gbuiltin_bls381::*;
use gstd::{msg, prelude::*, ActorId};
use hex_literal::hex;
type ArkScale<T> = ark_scale::ArkScale<T, { ark_scale::HOST_CALL }>;

const BUILTIN_BLS381: ActorId = ActorId::new(hex!(
    "6b6e292c382945e80bf51af2ba7fe9f458dcff81ae6075c46f9095e1bbecdc37"
));

#[derive(Debug, Encode, Decode, TypeInfo, Clone)]
pub struct VerifyingKeyBytes {
    pub alpha_g1_beta_g2: Vec<u8>,
    pub gamma_g2_neg_pc: Vec<u8>,
    pub delta_g2_neg_pc: Vec<u8>,
}

#[derive(Debug, Encode, Decode, TypeInfo, Clone)]
pub struct ProofBytes {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub c: Vec<u8>,
}

#[derive(Debug, Encode, Decode, TypeInfo, Clone)]
pub struct Groth16ZkVerify {
    vk: VerifyingKeyBytes,
    proof: ProofBytes,
    prepared_inputs_bytes: Vec<u8>,
}

#[gstd::async_main]
async fn main() {
    let Groth16ZkVerify {
        vk,
        proof,
        prepared_inputs_bytes,
    } = msg::load().expect("Unable to decode `Groth16ZkVerify`");

    let alpha_g1_beta_g2 = <ArkScale<<Bls12_381 as Pairing>::TargetField> as Decode>::decode(
        &mut vk.alpha_g1_beta_g2.as_slice(),
    )
    .unwrap();

    let gamma_g2_neg_pc =
        G2Affine::deserialize_uncompressed_unchecked(&*vk.gamma_g2_neg_pc).unwrap();

    let delta_g2_neg_pc =
        G2Affine::deserialize_uncompressed_unchecked(&*vk.delta_g2_neg_pc).unwrap();

    let a = G1Affine::deserialize_uncompressed_unchecked(&*proof.a).unwrap();

    let b = G2Affine::deserialize_uncompressed_unchecked(&*proof.b).unwrap();

    let c = G1Affine::deserialize_uncompressed_unchecked(&*proof.c).unwrap();

    let prepared_inputs =
        G1Affine::deserialize_uncompressed_unchecked(&*prepared_inputs_bytes).unwrap();
    let a: ArkScale<Vec<G1Affine>> = vec![a, prepared_inputs, c].into();
    let b: ArkScale<Vec<G2Affine>> = vec![b, gamma_g2_neg_pc, delta_g2_neg_pc].into();

    let miller_out = calculate_multi_miller_loop(a.encode(), b.encode()).await;

    let exp = calculate_exponentiation(miller_out).await;

    assert_eq!(exp, alpha_g1_beta_g2);
    
}

async fn calculate_multi_miller_loop(g1: Vec<u8>, g2: Vec<u8>) -> Vec<u8> {
    let request = Request::MultiMillerLoop { a: g1, b: g2 }.encode();

    let reply = msg::send_bytes_for_reply(BUILTIN_BLS381, &request, 0, 0)
        .expect("Failed to send message")
        .await
        .expect("Received error reply");

    let response = Response::decode(&mut reply.as_slice()).unwrap();
    let miller_out = match response {
        Response::MultiMillerLoop(v) => v,
        _ => unreachable!(),
    };
    miller_out
}

async fn calculate_exponentiation(f: Vec<u8>) -> ArkScale<<Bls12_381 as Pairing>::TargetField> {
    let request = Request::FinalExponentiation { f }.encode();

    let reply = msg::send_bytes_for_reply(BUILTIN_BLS381, &request, 0, 0)
        .expect("Failed to send message")
        .await
        .expect("Received error reply");
    let response = Response::decode(&mut reply.as_slice()).unwrap();
    let exp = match response {
        Response::FinalExponentiation(v) => {
            ArkScale::<<Bls12_381 as Pairing>::TargetField>::decode(&mut v.as_slice()).unwrap()
        }
        _ => unreachable!(),
    };
    exp
}
