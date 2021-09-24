#!/bin/bash

cd "$(dirname "$0")"
wasm-pack build --target web -- --features console_error_panic_hook

mkdir -p output
cargo r >output/crypto.js
cp pkg/sqrcp_client_bg.wasm output/crypto.wasm
cp www/main.js output/
