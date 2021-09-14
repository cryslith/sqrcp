use std::error::Error as _;
use std::fs::File;
use std::future::Future;
use std::io::{stdin, Read, Write};

use chrono::Utc;
use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg, ArgMatches};
use hyper::{
  http,
  service::{make_service_fn, service_fn},
  Body, Method, Request, Response, Server, StatusCode,
};
use itertools::Itertools;
use multipart::client::{HttpRequest, HttpStream, Multipart};
use pnet::datalink;
use qrcodegen::{QrCode, QrCodeEcc};
use regex::Regex;
use ring::{
  aead::{Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN},
  digest::{digest, SHA512},
  rand::{SecureRandom, SystemRandom},
};
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
  #[error("error running self-host server")]
  Hyper(#[from] hyper::Error),
  #[error(transparent)]
  IO(#[from] std::io::Error),
  #[error("upload failed")]
  Upload,
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
        .possible_values(&["inline", "self-host"])
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
    "webpage" => webpage(&matches, input, false)?,
    "inline-webpage" => webpage(&matches, input, true)?,
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

fn webpage(
  matches: &ArgMatches,
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

  let decryptjs = include_str!("decrypt.js");

  let host_decryptjs = if matches.value_of("host") == Some("self-host") {
    Some(decryptjs.to_string())
  } else {
    None
  };
  let host_ciphertext = if matches.value_of("uploader") == Some("self-host") {
    Some(ciphertext.clone())
  } else {
    None
  };
  let server = if host_decryptjs.is_some() || host_ciphertext.is_some() {
    let make_service = make_service_fn(move |_| {
      let host_decryptjs1 = host_decryptjs.clone();
      let host_ciphertext1 = host_ciphertext.clone();
      async move {
        Ok::<_, hyper::Error>(service_fn(move |req| {
          self_hoster(host_decryptjs1.clone(), host_ciphertext1.clone(), req)
        }))
      }
    });

    Some(Server::bind(&([0, 0, 0, 0], 0).into()).serve(make_service))
  } else {
    None
  };
  let mut server_addr = if let Some(ref server) = server {
    let mut addr = server.local_addr();
    let local_ip = datalink::interfaces().iter()
      .find(|x| !x.is_loopback() && !x.ips.is_empty())
      .ok_or(MainError::DetectLocalIP)?.ips[0].ip();
    addr.set_ip(local_ip);
    Some(addr)
  } else {
    None
  };

  let decryptjs_source = match matches.value_of("host").unwrap() {
    "self-host" => {
      let integrity = format!(
        "sha512-{}",
        base64::encode(digest(&SHA512, decryptjs.as_bytes()).as_ref())
      );
      DecryptSource::Hosted(format!("http://{}/decrypt.js", server_addr.unwrap()), integrity)
    }
    "inline" => DecryptSource::Unhosted(decryptjs.to_string()),
    _ => panic!("invalid host"),
  };

  let ciphertext_url = match matches.value_of("uploader").unwrap() {
    "test-inline" => format!(
      "data:application/octet-stream;base64,{}",
      base64::encode(ciphertext),
    ),
    "self-host" => format!("http://{}/ciphertext", server_addr.unwrap()),
    "file.io" => file_io_upload(&ciphertext[..])?,
    _ => panic!("invalid uploader"),
  };

  let mut context = Context::new();
  context.insert("inline", &inline);
  match decryptjs_source {
    DecryptSource::Hosted(url, integrity) => {
      context.insert("hosted", &true);
      context.insert("hosted_decrypt", &url);
      context.insert("hosted_decrypt_integrity", &integrity);
    }
    DecryptSource::Unhosted(source) => {
      context.insert("hosted", &false);
      context.insert("unhosted_decrypt", &source);
    }
  }
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
  let webpage = Tera::one_off(include_str!("receiver.html.tera"), &context, false)?;
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

async fn self_hoster(
  decrypt_js: Option<String>,
  ciphertext: Option<Vec<u8>>,
  req: Request<Body>,
) -> Result<Response<Body>, http::Error> {
  match (req.method(), req.uri().path(), decrypt_js, ciphertext) {
    (&Method::GET, "/decrypt.js", Some(decryptjs), _) => Response::builder()
      .header("Content-Type", "text/javascript")
      .header("Access-Control-Allow-Origin", "*")
      .body(decryptjs.into()),
    (&Method::GET, "/ciphertext", _, Some(ciphertext)) => Response::builder()
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

enum DecryptSource {
  Hosted(String, String),
  Unhosted(String),
}

fn file_io_upload(data: &[u8]) -> Result<String, MainError> {
  todo!()
  // let mut req = Multipart::from_request(MultipartUreq(ureq::post("https://file.io")))?;
  // req.write_stream("file", data, Some("file"), None)?;
  // let val = req.send()?.into_json()?;
  // if !val
  //   .get("success")
  //   .and_then(SerdeValue::as_bool)
  //   .unwrap_or(false)
  // {
  //   return Err(MainError::FileIO(
  //     val
  //       .get("message")
  //       .and_then(SerdeValue::as_str)
  //       .unwrap_or("[no message]")
  //       .to_string(),
  //   ));
  // }
  // match val.get("link").and_then(SerdeValue::as_str) {
  //   Some(x) => Ok(x.to_string()),
  //   None => Err(MainError::Upload),
  // }
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

impl OneNonceSequence {
  fn new(nonce: Nonce) -> Self {
    Self(Some(nonce))
  }
}

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
