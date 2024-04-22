#![no_std]

use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing};
use gbuiltin_bls381::*;
use gstd::{msg, prelude::*, ActorId};
use hex_literal::hex;
type ArkScale<T> = ark_scale::ArkScale<T, { ark_scale::HOST_CALL }>;

const G2_GENERATOR: [u8; 192] = [
    19, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160, 136, 39, 79, 101, 89, 107, 208, 208,
    153, 32, 182, 26, 181, 218, 97, 187, 220, 127, 80, 73, 51, 76, 241, 18, 19, 148, 93, 87, 229,
    172, 125, 5, 93, 4, 43, 126, 2, 74, 162, 178, 240, 143, 10, 145, 38, 8, 5, 39, 45, 197, 16, 81,
    198, 228, 122, 212, 250, 64, 59, 2, 180, 81, 11, 100, 122, 227, 209, 119, 11, 172, 3, 38, 168,
    5, 187, 239, 212, 128, 86, 200, 193, 33, 189, 184, 6, 6, 196, 160, 46, 167, 52, 204, 50, 172,
    210, 176, 43, 194, 139, 153, 203, 62, 40, 126, 133, 167, 99, 175, 38, 116, 146, 171, 87, 46,
    153, 171, 63, 55, 13, 39, 92, 236, 29, 161, 170, 169, 7, 95, 240, 95, 121, 190, 12, 229, 213,
    39, 114, 125, 110, 17, 140, 201, 205, 198, 218, 46, 53, 26, 173, 253, 155, 170, 140, 189, 211,
    167, 109, 66, 154, 105, 81, 96, 209, 44, 146, 58, 201, 204, 59, 172, 162, 137, 225, 147, 84,
    134, 8, 184, 40, 1,
];
const BUILTIN_BLS381: ActorId = ActorId::new(hex!(
    "6b6e292c382945e80bf51af2ba7fe9f458dcff81ae6075c46f9095e1bbecdc37"
));

#[derive(Default)]
pub struct Contract {
    g2_gen: G2Affine,
    pub_keys: Vec<G2Affine>,
}
static mut CONTRACT: Option<Contract> = None;

#[derive(Encode, Decode)]
pub enum HandleMessage {
    VerifyBlsSignature {
        // Ids of public keys that have signed the message
        signing_keys_ids: Vec<u8>,
        // Corresponding signatures
        signatures: Vec<Vec<u8>>,
        // The message that was signed
        message: Vec<u8>,
    },
}

#[derive(Encode, Decode)]
pub struct InitMessage {
    pub pub_keys: Vec<Vec<u8>>,
}

#[gstd::async_main]
async fn main() {
    let msg: HandleMessage = msg::load().expect("Unable to decode `HandleMessage`");
    let contract = unsafe { CONTRACT.as_mut().expect("The contract is not initialized") };

    match msg {
        HandleMessage::VerifyBlsSignature {
            signing_keys_ids,
            signatures,
            message,
        } => {
            let aggregate_pub_key = get_aggregate_key(&contract.pub_keys, &signing_keys_ids);
            let aggregate_signature = get_aggregate_signature(&signatures);
            verify_bls(
                message,
                aggregate_pub_key,
                aggregate_signature,
                contract.g2_gen,
            )
            .await;
        }
        // Add public key, remove public key, admins
        _ => todo!(),
    }
}

fn get_aggregate_key(keys: &[G2Affine], ids: &[u8]) -> G2Affine {
    let mut aggregate_pub_key: G2Affine = Default::default();
    for id in ids {
        let pub_key = keys
            .get(*id as usize)
            .expect("Index out of bounds: Public key ID does not exist");
        aggregate_pub_key = (aggregate_pub_key + pub_key).into();
    }
    aggregate_pub_key
}

fn get_aggregate_signature(signatures: &[Vec<u8>]) -> G1Affine {
    let mut aggregate_signature: G1Affine = Default::default();
    for signature in signatures.iter() {
        let signature = <ArkScale<<Bls12_381 as Pairing>::G1Affine> as Decode>::decode(
            &mut signature.as_slice(),
        )
        .expect("Unable to decode into signature from provided bytes");
        aggregate_signature = (aggregate_signature + signature.0).into();
    }
    aggregate_signature.into()
}

async fn verify_bls(
    message: Vec<u8>,
    aggregate_pub_key: G2Affine,
    aggregate_signature: G1Affine,
    g2_gen: G2Affine,
) {
    // Wrap the public key in a vector and encode it for cryptographic operations
    let aggregate_pub_key: ArkScale<Vec<G2Affine>> = vec![aggregate_pub_key.clone()].into();

    let miller_out1 = calculate_multi_miller_loop(message, aggregate_pub_key.encode()).await;

    let aggregate_signature: ArkScale<Vec<G1Affine>> = vec![aggregate_signature].into();
    let g2_gen: ArkScale<Vec<G2Affine>> = vec![g2_gen.clone()].into();
    let miller_out2 = calculate_multi_miller_loop(aggregate_signature.encode(), g2_gen.encode()).await;

    let exp1 = calculate_exponentiation(miller_out1).await;
    let exp2 = calculate_exponentiation(miller_out2).await;

    assert_eq!(exp1.0, exp2.0);
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

async fn calculate_exponentiation(f: Vec<u8>) -> ArkScale::<<Bls12_381 as Pairing>::TargetField> {
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

#[no_mangle]
extern "C" fn init() {
    let init_msg: InitMessage = msg::load().expect("Unable to decode `InitMessage`");

    let g2_gen_bytes = G2_GENERATOR.to_vec() ;
    let g2_gen = <ArkScale<<Bls12_381 as Pairing>::G2Affine> as Decode>::decode(
        &mut g2_gen_bytes.as_slice(),
    )
    .expect("Unable to decode the provided bytes into the generator of G2");

    let mut pub_keys = Vec::new();

    for pub_key_bytes in init_msg.pub_keys.iter() {
        let pub_key = <ArkScale<<Bls12_381 as Pairing>::G2Affine> as Decode>::decode(
            &mut pub_key_bytes.as_slice(),
        )
        .expect("Unable to decode the provided bytes into the element of G2");
        pub_keys.push(pub_key.0);
    }
    let contract = Contract {
        g2_gen: g2_gen.0,
        pub_keys,
    };

    unsafe { CONTRACT = Some(contract) }
}
