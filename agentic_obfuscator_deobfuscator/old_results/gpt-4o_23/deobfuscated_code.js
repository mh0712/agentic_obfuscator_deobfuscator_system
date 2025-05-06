// Deobfuscated and readable version

// Base64-decode function for obfuscation
function base64decode(encodedString) {
  return decodeURIComponent(
    atob(encodedString)
      .split('')
      .map((char) => '%' + ('00' + char.charCodeAt(0).toString(16)).slice(-2))
      .join('')
  );
}

let stringArray = [
  "YXBwbHk=",
  "aVhiS2E=",
  "cmV2ZXJzZQ==",
  "am9pbg==",
  "cmVwbGFjZQ==",
  "dG9VcHBlckNhc2U=",
  "ZnVuY3Rpb24gKlwoICpcKQ==",
  "Znl0Sno=",
  "dUJXb3o=",
  "XCtcKyAqKD86XzB4KD86W2EtZjAtOV0pezQsNn18KD86XGJ8XGQpW2EtejAtOV17MSw0fSg/OlxifFxkKSk=",
  "aW5pdA==",
  "dGVzdA==",
  "TFpKRHo=",
  "Y2hhaW4=",
  "aW5wdXQ=",
  "aW5jbHVkZXM=",
  "aGVsbG8gd29ybGQgZnJvbSBqYXZhc2NyaXB0",
  "T3JpZ2luYWwgU3RyaW5nOiA=",
  "UmV2ZXJzZWQgU3RyaW5nOiA=",
  "QVZackw=",
  "Q2FwaXRhbGl6ZWQgV29yZHM6IA==",
  "Q29udGFpbnMgJ3dvcmxkJzog",
  "d29ybGQ=",
  "c3RyaW5n",
  "d2hpbGUgKHRydWUpIHt9",
  "Y291bnRlcg==",
  "bGVuZ3Ro",
  "ZGVidQ==",
  "c3RhdGVPYmplY3Q=",
  "bE5TZHM=",
  "Y29uc3RydWN0b3I=",
  "WXltUGM=",
  "b3RScHk=",
  "UEtJVlE=",
  "cFJrV2Y=",
  "dGNMeHI=",
  "U1Z4a3c=",
  "Z2dlcg==",
  "Y2FsbA==",
  "YWN0aW9u",
  "WElwRko=",
  "S1RhU2s=",
  "eVdpdFE=",
  "R3R3REM=",
  "MHwyfDF8M3w0",
  "c3BsaXQ=",
  "Y2pyWks=",
  "cmV0dXJuIChmdW5jdGlvbigpIA==",
  "e30uY29uc3RydWN0b3IoInJldHVybiB0aGlzIikoICk=",
  "b25EbWw=",
  "Y29uc29sZQ==",
  "MHwxfDJ8M3w4fDV8NHw3fDY=",
  "bG9n",
  "d2Fybg==",
  "ZGVidWc=",
  "ZXhjZXB0aW9u",
  "ZXJyb3I=",
  "dHJhY2U=",
  "aW5mbw==",
].map(base64decode);

// Main logic functions
function testFunction(inputString) {
  // Reverses the input string and returns it
  return inputString.split('').reverse().join('');
}

function capitalizeFirstLetter(string) {
  // Capitalizes the first letter of each word
  return string.replace(/\b\w/g, char => char.toUpperCase());
}

function repeatString(inputString, times) {
  // Repeats the input string 'times' times
  return inputString.repeat(times);
}

// Example usage
let message = "hello world from javascript";
console.log("Original String: " + message);
console.log("Reversed String: " + testFunction(message));
console.log("Capitalized Words: " + capitalizeFirstLetter(message));
console.log("Repeated String: " + repeatString(message, 3));

// Set a regular interval to execute a function (placeholder example)
setInterval(() => {
  console.log("Interval function executed...");
}, 4000);
