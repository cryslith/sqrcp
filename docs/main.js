const S = window.sqrcp_client;

function base64Decode(s) {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0))
}

async function main(params) {
  const message = document.createElement("pre");
  message.textContent = "Loading...";
  document.body.appendChild(message);

  try {
    const { i: inline, c: cipherURL, k: keyBytes64, n: nonceBytes64, m: mimetype, f: filename, w: wasm } = params;

    await S.initSecure(wasm);
    S.set_panic_hook();
    const key = base64Decode(keyBytes64);
    const nonce = base64Decode(nonceBytes64);
    const response = await fetch(cipherURL, {mode: "cors"});
    if (!response.ok) {
      throw new Error(`fetching ciphertext: ${response.statusText}`);
    }

    const ciphertext = new Uint8Array(await response.arrayBuffer());
    const plaintext = S.unseal(key, nonce, ciphertext);

    if (inline) {
      const dataview = new DataView(plaintext.buffer);
      const shorts = [];
      for (let i = 0; i < dataview.byteLength; i += 2) {
        shorts.push(dataview.getUint16(i, true));
      }
      const text = String.fromCharCode.apply(null, shorts);
      const plaintextE = document.createElement("pre");
      plaintextE.textContent = text;
      document.body.appendChild(plaintextE);
    } else {
      const download = document.createElement("a");
      const blob = new Blob([plaintext], {type: mimetype});
      download.setAttribute("href", URL.createObjectURL(blob));
      download.setAttribute("download", filename);
      download.textContent = "Open file";
      document.body.appendChild(download);
    }
  } catch (e) {
    message.textContent = `error: ${e}`;
    throw e;
  }

  message.parentNode.removeChild(message);
}

main(P);
