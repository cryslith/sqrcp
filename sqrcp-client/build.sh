#!/bin/bash

cd "$(dirname "$0")"
wasm-pack build --target web -- --features console_error_panic_hook
