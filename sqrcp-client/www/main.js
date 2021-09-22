const S = window.sqrcp_client;

async function main(params) {
  const message = document.createElement("pre");
  message.textContent = "Loading...";
  document.body.appendChild(message);

  try {
    const { inline, ciphertext: cipherURL, key: keyBytes, nonce: nonceBytes, mimetype, filename, wasm, wasm_integrity } = params;

    await S.init(fetch(wasm), {
      integrity: wasm_integrity
    });
    S.set_panic_hook();
    const key = new Uint8Array(keyBytes);
    const nonce = new Uint8Array(nonceBytes);
    const response = await fetch(cipherURL);
    if (!response.ok) {
      throw new Error(`fetching ciphertext: ${response.statusText}`);
    }

    const ciphertext = new Uint8Array(await response.arrayBuffer());
    const plaintext = S.unseal(key, nonce, ciphertext);

    if (inline) {
      const dataview = new DataView(plaintext);
      const shorts = [];
      for (let i = 0; i < dataview.byteLength; i += 2) {
        shorts.push(dataview.getUint16(i, true));
      }
      const text = String.fromCharCode.apply(null, shorts);
      const plaintext = document.createElement("pre");
      plaintext.textContent = text;
      document.body.appendChild(plaintext);
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
