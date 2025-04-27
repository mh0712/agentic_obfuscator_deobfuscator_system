const CryptoJS = require("crypto-js");
const pako = require("pako");

// Anti-Debug function
function generateAntiDebug() {
  return `
(function(){
    function detectDebugger() {
        const start = Date.now();
        debugger;
        if (Date.now() - start > 100) {
            window.location.reload();
        }
    }
    setInterval(detectDebugger, 1000);
})();`;
}

function encryptData(data, key, iv) {
  const encrypted = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(data), key, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });
  return encrypted.toString();
}

function buildLoader(encryptedPayload, encryptedKey, encryptedIV) {
  return `
CryptoJS = require('crypto-js');
pako = require('pako');
(function(){
    ${generateAntiDebug()}

    const encryptedData = "${encryptedPayload}";
    const encryptedKey = "${encryptedKey}";
    const encryptedIV = "${encryptedIV}";

    function decryptKeyAndIV() {
        const decryptedKey = CryptoJS.AES.decrypt(encryptedKey, 'randomSaltForKey').toString(CryptoJS.enc.Utf8);
        const decryptedIV = CryptoJS.AES.decrypt(encryptedIV, 'randomSaltForIV').toString(CryptoJS.enc.Utf8);
        return { key: CryptoJS.enc.Hex.parse(decryptedKey), iv: CryptoJS.enc.Hex.parse(decryptedIV) };
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
            const binaryString = Array.from(compressedData, c => c.charCodeAt(0));
            const decompressed = pako.inflate(new Uint8Array(binaryString), { to: 'string' });

            eval(decompressed);
        } catch (e) {
            console.error("Decryption or execution failed:", e);
        }
    }

    decryptAndRun();
})();`;
}

async function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

async function obfuscateFromStdin() {
  const code = await readStdin();

  // 1. Compress
  const compressed = pako.deflate(code);

  // 2. Generate AES Key & IV
  const aesKey = CryptoJS.lib.WordArray.random(16);
  const iv = CryptoJS.lib.WordArray.random(16);

  // 3. Encrypt the key and IV themselves
  const encryptedKey = encryptData(
    aesKey.toString(CryptoJS.enc.Hex),
    "randomSaltForKey",
    "randomSaltForKey"
  );
  const encryptedIV = encryptData(
    iv.toString(CryptoJS.enc.Hex),
    "randomSaltForIV",
    "randomSaltForIV"
  );

  // 4. Encrypt the main payload
  const compressedString = String.fromCharCode(...compressed);
  const encrypted = CryptoJS.AES.encrypt(
    CryptoJS.enc.Latin1.parse(compressedString),
    aesKey,
    { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
  );

  const encryptedBase64 = CryptoJS.enc.Base64.stringify(encrypted.ciphertext);

  // 5. Build loader
  const loader = buildLoader(encryptedBase64, encryptedKey, encryptedIV);

  // 6. Output to stdout
  console.log(loader);
}

if (require.main === module) {
  obfuscateFromStdin().catch((err) => {
    console.error("[!] Obfuscation failed:", err);
    process.exit(1);
  });
}
