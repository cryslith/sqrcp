async function decrypt(key, nonce, ciphertext) {
  return crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: nonce,
    },
    await crypto.subtle.importKey(
      "raw",
      key,
      {name: "AES-GCM"},
      false,
      ["decrypt"],
    ),
    ciphertext,
  );
}

async function readAll(stream, length) {
  if (length < 64) {
    length = 64;
  }
  let buffer = new Uint8Array(length);
  let n = 0;
  for (;;) {
    let {done, value} = await stream.read();
    if (done) {
      break;
    }
    while (n + value.length > buffer.length) {
      let buffer2 = new Uint8Array(buffer.length * 2);
      buffer2.set(buffer, 0);
      buffer = buffer2;
    }
    buffer.set(value, n);
    n += value.length;
  }
  return buffer.slice(0, n);
}

async function main(params) {
  const { inline, ciphertext, key, nonce, mimetype, filename } = params;

  let message = document.getElementById("message");

  try {
    let key = new Uint8Array(key);
    let nonce = new Uint8Array(nonce);
    let response = await fetch(ciphertext);
    if (!response.ok) {
      throw new Error(`fetching ciphertext: ${response.statusText}`);
    }
    // // response.arrayBuffer() is unfortunately not supported
    // // on major mobile browsers yet
    // let ciphertext = await readAll(response.body.getReader(),
    //                                parseInt(response.headers.get("content-length"), 10) || -1);
    let ciphertext = await response.arrayBuffer();
    let plaintext = await decrypt(key, nonce, ciphertext);

    if (inline) {
      let dataview = new DataView(plaintext);
      let shorts = [];
      for (let i = 0; i < dataview.byteLength; i += 2) {
        shorts.push(dataview.getUint16(i, true));
      }
      let text = String.fromCharCode.apply(null, shorts);
      document.getElementById("plaintext").textContent = text;
    } else {
      let download = document.getElementById("download");
      let blob = new Blob([plaintext], {type: mimetype});
      download.setAttribute("href", URL.createObjectURL(blob));
      download.setAttribute("download", filename);
      download.textContent = "Open file";
    }
  } catch (e) {
    message.textContent = `error: ${e}`;
    return;
  }

  console.log("success");
  message.parentNode.removeChild(message);
}
