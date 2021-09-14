#[macro_use]
pub mod utils;

use std::convert::TryInto;

use ring::{
  aead::{Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN, OpeningKey},
};
use wasm_bindgen::prelude::*;
use thiserror::Error;

fn trace<T>(x: T) -> T
where
  T: std::fmt::Debug,
{
  log!("[rust] {:?}", x);
  x
}

#[wasm_bindgen]
pub fn unseal(key: &[u8], nonce: &[u8], ciphertext: Vec<u8>) -> Result<Vec<u8>, JsValue> {
  let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| JsValue::from_str("wrong nonce length"))?;
  let mut opening_key = OpeningKey::new(
    UnboundKey::new(&AES_256_GCM, key).map_err(|_| JsValue::from_str("key creation failed"))?,
    OneNonceSequence(Some(Nonce::assume_unique_for_key(nonce))),
  );
  let mut in_out = ciphertext;
  opening_key.open_in_place(Aad::empty(), &mut in_out).map_err(|_| JsValue::from_str("decryption failed"))?;
  Ok(in_out)
}

struct OneNonceSequence(Option<Nonce>);

impl NonceSequence for OneNonceSequence {
  fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
    self.0.take().ok_or(ring::error::Unspecified)
  }
}
