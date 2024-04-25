## BLS Signatures

BLS (Boneh-Lynn-Shacham) is a cryptographic signature scheme developed by Dan Boneh, Ben Lynn, and Hovav Shacham. It is particularly notable for its use of bilinear pairings, a type of mathematical operation on elliptic curves that facilitates certain properties which are highly beneficial in various cryptographic protocols. This signature scheme is renowned for its ability to produce short signatures and support signature aggregation - a feature that significantly enhances scalability in systems such as blockchain networks.

### The Basics of BLS Signature Scheme
At its core, the BLS signature scheme involves three main processes: 
- key generation;
- signing;
- verification. 

Here's a breakdown of each:

#### Key Generation (KeyGen):
A user generates a private key, `α`, chosen at random.
The corresponding public key is computed as 
```
pk = α * g1
``` 
where `g1` is a generator of the group `G1`.

#### Signing:
To sign a message m, the signer computes the signature as 
```
σ = α * H(m)
```
where `H(m)` is a cryptographic hash function mapping `m` to a point on an elliptic curve in the group `G2`.

#### Verification:
A signature `σ` is verified by checking whether 
```
e(g1, σ) = e(pk, H(m))
```
holds true. Here, `e` is a bilinear pairing function.

### BLS12-381: A Pairing-Friendly Curve
BLS12-381 is an elliptic curve that offers efficient operations for cryptographic pairings, making it highly suitable for implementing BLS signatures. It supports the construction of secure, performant, and concise cryptographic protocols.

#### Advanced Features of BLS
- `Aggregation`
One of the most powerful features of BLS signatures is their ability to be aggregated. This means multiple signatures can be combined into a single signature. This aggregated signature, along with an aggregated public key, can be verified against a single message or multiple distinct messages, depending on the scheme's design.

- `Aggregate Public Key`: The sum of individual public keys.
- `Aggregate Signature`: The sum of individual signatures.
The verification of an aggregate signature remains efficient, involving only a single pairing operation, which checks:
```
e(g1, aggregate_signature) = e(aggregate_public_key, H(m))
```
#### Cryptographic Pairing in BLS
Pairing operations are the heart of the BLS signature scheme. In practice, these can be broken down into:

- **Miller Loop**: Computes an intermediate pairing result.
- **Final Exponentiation**: Converts the Miller loop output into a final pairing result, which is used for verification.
These operations are computationally intensive but crucial for the security and functionality of BLS signatures.

#### Implementing BLS Signatures in Smart Contracts on the Vara Network

 Vara network includes support for cryptographic operations like the Miller loop and exponentiation:
- **Miller loop**
```rust
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
```
- **Final exponentiation**
```rust
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
```

Then, the BLS signature verification:
```rust
async fn verify_bls(
    message: Vec<u8>,
    aggregate_pub_key: G2Affine,
    aggregate_signature: G1Affine,
    g2_gen: G2Affine,
) {
    // Convert inputs for cryptographic processing.
    let message_encoded = ArkScale::<<Bls12_381 as Pairing>::G1Affine>::encode(&message);
    let aggregate_pub_key_encoded = ArkScale::<<Bls12_381 as Pairing>::G2Affine>::encode(&aggregate_pub_key);
    let aggregate_signature_encoded = ArkScale::<<Bls12_381 as Pairing>::G1Affine>::encode(&aggregate_signature);

    // Calculate the two sides of the verification equation using Miller loops.
    let left_side = calculate_miller_loop(message_encoded, aggregate_signature_encoded).await;
    let right_side = calculate_miller_loop(aggregate_pub_key_encoded, G2_GENERATOR.to_vec()).await;

    // Complete the verification by performing final exponentiation.
    let final_left = calculate_exponentiation(left_side).await;
    let final_right = calculate_exponentiation(right_side).await;

    // Assert equality to verify the signature.
    assert_eq!(final_left, final_right, "Signature verification failed");
}
```