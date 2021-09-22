use std::error::Error as _;
use std::fs::File;
use std::future::Future;
use std::io::{stdin, Cursor, Read};

use chrono::Utc;
use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg, ArgMatches};
use hyper::{
  http,
  service::{make_service_fn, service_fn},
  Body, Client, Method, Request, Response, Server, StatusCode,
};
use hyper_multipart_rfc7578::client::multipart;
use itertools::Itertools;
use pnet::datalink;
use qrcodegen::{QrCode, QrCodeEcc};
use regex::Regex;
use ring::{
  aead::{Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN},
  digest::{digest, SHA512},
  rand::{SecureRandom, SystemRandom},
};
use serde_json::Value as SerdeValue;
use tera::{Context, Tera};
use thiserror::Error;

#[derive(Debug, Error)]
enum MainError {
  #[error("couldn't autodetect local IP")]
  DetectLocalIP,
  #[error("encryption failed")]
  EncryptionFailed,
  #[error("file.io returned error: {0}")]
  FileIO(String),
  #[error(transparent)]
  HTTP(#[from] http::Error),
  #[error(transparent)]
  Hyper(#[from] hyper::Error),
  #[error(transparent)]
  IO(#[from] std::io::Error),
  #[error("upload failed")]
  Upload,
  #[error(transparent)]
  SerdeJson(#[from] serde_json::Error),
  #[error("webpage templating error")]
  Template(#[from] tera::Error),
  #[error("failed to transcode plaintext for inline display")]
  TranscodePlaintext(#[source] std::str::Utf8Error),
  #[error(transparent)]
  QrCode(#[from] qrcodegen::DataTooLong),
}

impl From<ring::error::Unspecified> for MainError {
  fn from(_: ring::error::Unspecified) -> Self {
    Self::EncryptionFailed
  }
}

#[tokio::main]
async fn main() {
  let matches = App::new(crate_name!())
    .version(crate_version!())
    .author(crate_authors!())
    .about(crate_description!())
    .arg(
      Arg::from_usage("-m, --mode=[MODE]")
        .possible_values(&["data", "webpage", "inline-webpage"])
        .default_value("webpage"),
    )
    .arg(
      Arg::from_usage("-h, --host=[HOST] 'where javascript is hosted'")
        .possible_values(&["self-host"])
        .default_value("self-host"),
    )
    .arg(
      Arg::from_usage("-u, --uploader=[UPLOADER] 'where to upload ciphertext'")
        .possible_values(&["test-inline", "self-host", "file.io"])
        .default_value("self-host"),
    )
    .arg(
      Arg::from_usage("-o, --output=[OUTPUT] 'output type'")
        .possible_values(&["print", "qrcode"])
        .default_value("print"),
    )
    .arg_from_usage("--data=[DATA] 'specify input data directly instead of reading file'")
    .arg(Arg::from_usage(
      "--filename=[FILENAME] 'filename of download'",
    ))
    .arg(
      Arg::from_usage("--mimetype=[MIMETYPE] 'mime type of download")
        .default_value("application/octet-stream"),
    )
    .arg(
      Arg::from_usage("[file]")
        .required_unless("data")
        .conflicts_with("data"),
    )
    .get_matches();

  std::process::exit(match run(matches).await {
    Ok(_) => 0,
    Err(e) => {
      eprintln!("error: {}", e);
      let mut e = e.source();
      while let Some(c) = e {
        eprintln!("caused by: {}", c);
        e = c.source();
      }
      1
    }
  });
}

async fn run(matches: ArgMatches<'_>) -> Result<(), MainError> {
  // need a Vec for ring's encryption
  let input: Vec<u8> = match (matches.value_of("data"), matches.value_of("file")) {
    (None, None) | (Some(_), Some(_)) => panic!("need data xor file"),
    (Some(x), None) => x.as_bytes().to_owned(),
    (None, Some(f)) => {
      let mut buffer = vec![];
      if f == "-" {
        stdin().read_to_end(&mut buffer)?;
      } else {
        File::open(f)?.read_to_end(&mut buffer)?;
      }
      buffer
    }
  };

  let (output, server) = match matches.value_of("mode").unwrap() {
    "data" => (data_url(&matches, &input[..])?, None),
    "webpage" => webpage(&matches, input, false).await?,
    "inline-webpage" => webpage(&matches, input, true).await?,
    _ => panic!("invalid mode"),
  };

  match matches.value_of("output").unwrap() {
    "print" => println!("{}", output),
    "qrcode" => output_qrcode(&output[..])?,
    _ => panic!("invalid output"),
  }

  if let Some(server) = server {
    server.await?;
  }
  Ok(())
}

struct SealedMessage {
  key: Vec<u8>,
  nonce: [u8; NONCE_LEN],
  ciphertext: Vec<u8>,
}

fn data_url(matches: &ArgMatches, data: &[u8]) -> Result<String, MainError> {
  Ok(format!(
    "data:{};base64,{}",
    matches.value_of("mimetype").unwrap(),
    base64::encode(data),
  ))
}

async fn webpage(
  matches: &ArgMatches<'_>,
  mut plaintext: Vec<u8>,
  inline: bool,
) -> Result<
  (
    String,
    Option<impl Future<Output = Result<(), hyper::Error>>>,
  ),
  MainError,
> {
  let rng = SystemRandom::new();

  if inline {
    plaintext = std::str::from_utf8(&plaintext[..])
      .map_err(MainError::TranscodePlaintext)?
      .encode_utf16()
      .flat_map(|x| x.to_le_bytes().to_vec())
      .collect();
  }

  let SealedMessage {
    key,
    nonce,
    ciphertext,
  } = seal(&rng, plaintext)?;

  let main_js = include_str!("../../sqrcp-client/www/main.js");
  let mut crypto_js = include_str!("../../sqrcp-client/pkg/sqrcp_client.js").to_owned();
  crypto_js.push_str(include_str!(
    "../../sqrcp-client/www/sqrcp_client_expose.js"
  ));
  let crypto_wasm = include_bytes!("../../sqrcp-client/pkg/sqrcp_client_bg.wasm");

  let mut content = HostedContent::default();
  if matches.value_of("host") == Some("self-host") {
    content.main_js = Some(main_js.to_owned());
    content.crypto_js = Some(crypto_js.clone());
    content.crypto_wasm = Some(crypto_wasm.to_vec());
  }
  if matches.value_of("uploader") == Some("self-host") {
    content.ciphertext = Some(ciphertext.clone());
  }

  let server = if content != HostedContent::default() {
    let make_service = make_service_fn(move |_| {
      let content = content.clone();
      async move { Ok::<_, hyper::Error>(service_fn(move |req| self_hoster(content.clone(), req))) }
    });

    Some(Server::bind(&([0, 0, 0, 0], 0).into()).serve(make_service))
  } else {
    None
  };
  let server_addr = if let Some(ref server) = server {
    let mut addr = server.local_addr();
    let local_ip = datalink::interfaces()
      .iter()
      .find(|x| !x.is_loopback() && !x.ips.is_empty())
      .ok_or(MainError::DetectLocalIP)?
      .ips[0]
      .ip();
    addr.set_ip(local_ip);
    Some(addr)
  } else {
    None
  };

  let js_source = match matches.value_of("host").unwrap() {
    "self-host" => {
      let main_js_integrity = format!(
        "sha512-{}",
        base64::encode(digest(&SHA512, main_js.as_bytes()).as_ref())
      );
      let crypto_js_integrity = format!(
        "sha512-{}",
        base64::encode(digest(&SHA512, crypto_js.as_bytes()).as_ref())
      );
      let crypto_wasm_integrity = format!(
        "sha512-{}",
        base64::encode(digest(&SHA512, crypto_wasm).as_ref())
      );
      let base = server_addr.unwrap();
      JsSource {
        main_js: format!("http://{}/main.js", base),
        crypto_js: format!("http://{}/crypto.js", base),
        crypto_wasm: format!("http://{}/crypto.wasm", base),
        main_js_integrity,
        crypto_js_integrity,
        crypto_wasm_integrity,
      }
    }
    _ => panic!("invalid host"),
  };

  let ciphertext_url = match matches.value_of("uploader").unwrap() {
    "test-inline" => format!(
      "data:application/octet-stream;base64,{}",
      base64::encode(ciphertext),
    ),
    "self-host" => format!("http://{}/ciphertext", server_addr.unwrap()),
    "file.io" => file_io_upload(Cursor::new(ciphertext)).await?,
    _ => panic!("invalid uploader"),
  };

  let mut context = Context::new();
  context.insert("inline", &inline);

  context.insert("hosted_main", &js_source.main_js);
  context.insert("hosted_main_integrity", &js_source.main_js_integrity);
  context.insert("hosted_crypto", &js_source.crypto_js);
  context.insert("hosted_crypto_integrity", &js_source.crypto_js_integrity);
  context.insert("hosted_crypto_wasm", &js_source.crypto_wasm);
  context.insert(
    "hosted_crypto_wasm_integrity",
    &js_source.crypto_wasm_integrity,
  );

  context.insert("key", &format!("[{}]", key.into_iter().join(", ")));
  context.insert("nonce", &format!("[{}]", nonce.iter().join(", ")));
  context.insert("ciphertext", &ciphertext_url);
  context.insert("mimetype", matches.value_of("mimetype").unwrap());
  context.insert(
    "filename",
    &matches
      .value_of("filename")
      .map(ToString::to_string)
      .unwrap_or_else(|| format!("transfer-{}", Utc::now().format("%F-%T"))),
  );
  let webpage = Tera::one_off(
    include_str!("../../sqrcp-client/www/receiver.html.tera"),
    &context,
    false,
  )?;
  let webpage = Regex::new(r#"[[:space:]]+"#)
    .unwrap()
    .replace_all(&webpage[..], " ");
  Ok((
    format!(
      "data:text/html;charset=utf-8;base64,{}",
      base64::encode(webpage.as_bytes()),
    ),
    server,
  ))
}

#[derive(Clone, Default, PartialEq)]
struct HostedContent {
  main_js: Option<String>,
  crypto_js: Option<String>,
  crypto_wasm: Option<Vec<u8>>,
  ciphertext: Option<Vec<u8>>,
}

async fn self_hoster(
  content: HostedContent,
  req: Request<Body>,
) -> Result<Response<Body>, http::Error> {
  match (req.method(), req.uri().path(), content) {
    (
      &Method::GET,
      "/main.js",
      HostedContent {
        main_js: Some(main_js),
        ..
      },
    ) => Response::builder()
      .header("Content-Type", "text/javascript")
      .header("Access-Control-Allow-Origin", "*")
      .body(main_js.into()),
    (
      &Method::GET,
      "/crypto.js",
      HostedContent {
        crypto_js: Some(crypto_js),
        ..
      },
    ) => Response::builder()
      .header("Content-Type", "text/javascript")
      .header("Access-Control-Allow-Origin", "*")
      .body(crypto_js.into()),
    (
      &Method::GET,
      "/crypto.wasm",
      HostedContent {
        crypto_wasm: Some(crypto_wasm),
        ..
      },
    ) => Response::builder()
      .header("Content-Type", "application/wasm")
      .header("Access-Control-Allow-Origin", "*")
      .body(crypto_wasm.into()),
    (
      &Method::GET,
      "/ciphertext",
      HostedContent {
        ciphertext: Some(ciphertext),
        ..
      },
    ) => Response::builder()
      .header("Content-Type", "application/octet-stream")
      .header("Access-Control-Allow-Origin", "*")
      .body(ciphertext.into()),
    _ => {
      let mut not_found = Response::default();
      *not_found.status_mut() = StatusCode::NOT_FOUND;
      Ok(not_found)
    }
  }
}

struct JsSource {
  main_js: String,
  main_js_integrity: String,
  crypto_js: String,
  crypto_js_integrity: String,
  crypto_wasm: String,
  crypto_wasm_integrity: String,
}

async fn file_io_upload(data: impl Read + Send + Sync + 'static) -> Result<String, MainError> {
  let client = Client::new();
  let mut form = multipart::Form::default();
  form.add_reader_file("file", data, "file");
  let req = form.set_body_convert::<hyper::Body, multipart::Body>(Request::post("https://file.io"))?;
  let val: SerdeValue =
    serde_json::from_slice(&hyper::body::to_bytes(client.request(req).await?.into_body()).await?)?;

  if !val
    .get("success")
    .and_then(SerdeValue::as_bool)
    .unwrap_or(false)
  {
    return Err(MainError::FileIO(
      val
        .get("message")
        .and_then(SerdeValue::as_str)
        .unwrap_or("[no message]")
        .to_string(),
    ));
  }
  match val.get("link").and_then(SerdeValue::as_str) {
    Some(x) => Ok(x.to_string()),
    None => Err(MainError::Upload),
  }
}

fn output_qrcode(data: &str) -> Result<(), MainError> {
  let qr = QrCode::encode_text(data, QrCodeEcc::Low)?;
  let svg = qr.to_svg_string(10);
  println!("{}", svg);
  Ok(())
}

fn seal(rng: &impl SecureRandom, plaintext: Vec<u8>) -> Result<SealedMessage, MainError> {
  let mut key_bytes = vec![0; AES_256_GCM.key_len()];
  rng.fill(&mut key_bytes[..])?;
  let (nonce, raw_nonce) = get_random_nonce(rng);
  let mut key = SealingKey::new(
    UnboundKey::new(&AES_256_GCM, &key_bytes)?,
    OneNonceSequence(Some(nonce)),
  );
  let mut in_out = plaintext;
  key.seal_in_place_append_tag(Aad::empty(), &mut in_out)?;
  Ok(SealedMessage {
    key: key_bytes,
    nonce: raw_nonce,
    ciphertext: in_out,
  })
}

struct OneNonceSequence(Option<Nonce>);

impl NonceSequence for OneNonceSequence {
  fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
    self.0.take().ok_or(ring::error::Unspecified)
  }
}

fn get_random_nonce(rng: &impl SecureRandom) -> (Nonce, [u8; NONCE_LEN]) {
  let mut raw_nonce = [0u8; NONCE_LEN];
  rng.fill(&mut raw_nonce).unwrap();
  (Nonce::assume_unique_for_key(raw_nonce), raw_nonce)
}
