use std::error::Error as _;
use std::io::{stdin, Read, Write};

use chrono::Utc;
use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg, ArgMatches};
use itertools::Itertools;
use multipart::client::{HttpRequest, HttpStream, Multipart};
use regex::Regex;
use ring::{
  aead::{Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN},
  rand::{SecureRandom, SystemRandom},
};
use tera::{Context, Tera};
use thiserror::Error;
use ureq::SerdeValue;

#[derive(Debug, Error)]
enum MainError {
  #[error(transparent)]
  IO(#[from] std::io::Error),
  #[error("encryption failed")]
  EncryptionFailed,
  #[error("file.io returned error: {0}")]
  FileIO(String),
  #[error("upload failed")]
  Upload,
  #[error("webpage templating error")]
  Template(#[from] tera::Error),
  #[error("failed to transcode plaintext for inline display")]
  TranscodePlaintext(#[source] std::str::Utf8Error),
}

impl From<ring::error::Unspecified> for MainError {
  fn from(_: ring::error::Unspecified) -> Self {
    Self::EncryptionFailed
  }
}

fn main() {
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
      Arg::from_usage("-u, --uploader=[UPLOADER]")
        .possible_values(&["test-inline", "file.io"])
        .default_value("file.io"),
    )
    .arg(
      Arg::from_usage("-o, --output=[OUTPUT] 'output type'")
        .possible_values(&["print", "qrcode"])
        .default_value("print"),
    )
    .arg_from_usage("--data=[DATA] 'specify input data directly instead of reading stdin'")
    .arg(Arg::from_usage(
      "--filename=[FILENAME] 'filename of download'",
    ))
    .arg(
      Arg::from_usage("--mimetype=[MIMETYPE] 'mime type of download")
        .default_value("application/octet-stream"),
    )
    .get_matches();

  std::process::exit(match run(matches) {
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

fn run(matches: ArgMatches) -> Result<(), MainError> {
  let input = match matches.value_of("data") {
    Some(x) => x.as_bytes().to_owned(),
    None => {
      let mut buffer = vec![];
      stdin().read_to_end(&mut buffer)?;
      buffer
    }
  };

  let output = match matches.value_of("mode").unwrap() {
    "data" => data_url(&matches, &input[..]),
    "webpage" => webpage(&matches, input, false),
    "inline-webpage" => webpage(&matches, input, true),
    _ => panic!("invalid mode"),
  }?;

  match matches.value_of("output").unwrap() {
    "print" => {
      println!("{}", output);
      Ok(())
    }
    "qrcode" => output_qrcode(&output[..]),
    _ => panic!("invalid output"),
  }
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
) -> Result<String, MainError> {
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

  let ciphertext_url = match matches.value_of("uploader").unwrap() {
    "test-inline" => format!(
      "data:application/octet-stream;base64,{}",
      base64::encode(ciphertext),
    ),
    "file.io" => file_io_upload(&ciphertext[..])?,
    _ => panic!("invalid uploader"),
  };

  let mut context = Context::new();
  context.insert("inline", &inline);
  context.insert("key", &format!("[{}]", key.into_iter().join(", ")));
  context.insert("nonce", &format!("[{}]", nonce.iter().join(", ")));
  context.insert("ciphertext_url", &ciphertext_url);
  context.insert("download_mimetype", matches.value_of("mimetype").unwrap());
  context.insert(
    "download_filename",
    &matches
      .value_of("filename")
      .map(ToString::to_string)
      .unwrap_or_else(|| format!("transfer-{}", Utc::now().format("%F-%T"))),
  );
  let webpage = Tera::one_off(include_str!("receiver.html.tera"), &context, false)?;
  let webpage = Regex::new(r#"[[:space:]]+"#)
    .unwrap()
    .replace_all(&webpage[..], " ");
  Ok(format!(
    "data:text/html;charset=utf-8;base64,{}",
    base64::encode(webpage.as_bytes()),
  ))
}

fn file_io_upload(mut data: &[u8]) -> Result<String, MainError> {
  let mut req = Multipart::from_request(MultipartUreq(ureq::post("https://file.io")))?;
  req.write_stream("file", &mut data, Some("file"), None)?;
  let val = req.send()?.into_json()?;
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

fn output_qrcode(_data: &str) -> Result<(), MainError> {
  todo!();
}

fn seal(rng: &impl SecureRandom, plaintext: Vec<u8>) -> Result<SealedMessage, MainError> {
  let mut key_bytes = vec![0; AES_256_GCM.key_len()];
  rng.fill(&mut key_bytes[..])?;
  let (nonce, raw_nonce) = get_random_nonce(rng);
  let mut key = SealingKey::new(
    UnboundKey::new(&AES_256_GCM, &key_bytes)?,
    OneNonceSequence::new(nonce),
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

struct MultipartUreq(ureq::Request);
struct MultipartBuffer(ureq::Request, Vec<u8>);

impl HttpRequest for MultipartUreq {
  type Stream = MultipartBuffer;
  type Error = std::io::Error;

  fn apply_headers(&mut self, boundary: &str, content_len: Option<u64>) -> bool {
    self.0.set(
      "Content-Type",
      &format!(r#"multipart/form-data;boundary="{}""#, boundary)[..],
    );
    if let Some(len) = content_len {
      self.0.set("Content-Length", &len.to_string()[..]);
    }
    true
  }

  fn open_stream(self) -> Result<Self::Stream, Self::Error> {
    Ok(MultipartBuffer(self.0, vec![]))
  }
}

impl Write for MultipartBuffer {
  fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
    self.1.write(buf)
  }

  fn flush(&mut self) -> Result<(), std::io::Error> {
    self.1.flush()
  }
}

impl HttpStream for MultipartBuffer {
  type Request = MultipartUreq;
  type Response = ureq::Response;
  type Error = std::io::Error;

  fn finish(mut self) -> Result<Self::Response, Self::Error> {
    Ok(self.0.send_bytes(&self.1[..]))
  }
}
