use ring::digest::{digest, SHA512};
use tera::{Context, Tera};

fn main() {
  let wasm = include_bytes!("../pkg/sqrcp_client_bg.wasm");
  let wasm_integrity = format!("sha512-{}", base64::encode(digest(&SHA512, wasm).as_ref()));

  let mut context = Context::new();
  context.insert("wasm_integrity", &wasm_integrity);
  let sqrcp_client_expose = Tera::one_off(
    include_str!("../www/sqrcp_client_expose.js.tera"),
    &context,
    false,
  )
  .unwrap();

  let mut crypto_js = include_str!("../pkg/sqrcp_client.js").to_owned();
  crypto_js.push_str(&sqrcp_client_expose);
  print!("{}", crypto_js);
}
