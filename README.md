
## Building the contract
### ⚙️ Install Rust

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### ⚒️ Add specific toolchains

```shell
rustup toolchain add nightly
rustup target add wasm32-unknown-unknown --toolchain nightly
```
### 🏗️ Build

```shell
cargo build --release
```
## Running the tests

There are 2 tests for the contract:
- `gtest_test.rs`: tests the contract on-chain using the [`g-client`](https://docs.gear.rs/gclient/);
- `gtclient_test.rs`: tests the contract off-chain using [`gtest`](https://docs.gear.rs/gtest/) off-chain to verify its logic

To run the test off-chain:
```
cargo test bn_verify_gtest --release
```

To run the test on-chain you first need to run a Gear node.

Clone the git repo:
```
git clone https://github.com/gear-tech/gear.git
```
Build the node:
```
make node-release
```
Run the node:
```
./target/release/gear --chain=vara-dev --tmp --validator --alice
```

And then run the test:
```
cargo test bn_verify_node --release
```