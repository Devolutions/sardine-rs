#!/bin/sh
cargo +nightly build --target wasm32-unknown-unknown --features "wasm" --release
mkdir -p wasm
wasm-bindgen --browser ../target/wasm32-unknown-unknown/release/sardine.wasm --out-dir ./wasm