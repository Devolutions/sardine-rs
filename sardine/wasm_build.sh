#!/bin/sh
cargo +nightly build --example wasm --target wasm32-unknown-unknown --features "wasm" --release
mkdir -p wasm
cp ../target/wasm32-unknown-unknown/release/examples/wasm.wasm ../target/wasm32-unknown-unknown/release/examples/sardine.wasm
wasm-bindgen --no-modules ../target/wasm32-unknown-unknown/release/examples/sardine.wasm --out-dir ./wasm
