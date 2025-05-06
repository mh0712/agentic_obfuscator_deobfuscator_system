// Decoding function for Base64 encoded strings
function decodeBase64(encodedStr) {
  return decodeURIComponent(
    Array.prototype.map
      .call(atob(encodedStr), function (char) {
        return "%" + ("00" + char.charCodeAt(0).toString(16)).slice(-2);
      })
      .join("")
  );
}

// Decoded strings from the obfuscated array
const strings = [
  "split", // "c3BsaXQ="
  "reverse", // "cmV2ZXJzZQ=="
  "join", // "am9pbg=="
  "replace", // "cmVwbGFjZQ=="
  "toUpperCase", // "dG9VcHBlckNhc2U="
  "includes", // "aW5jbHVkZXM="
  "hello world from javascript", // "aGVsbG8gd29ybGQgZnJvbSBqYXZhc2NyaXB0"
  "log", // "bG9n"
  "Original String: ", // "T3JpZ2luYWwgU3RyaW5nOiA="
  "Reversed String: ", // "UmV2ZXJzZWQgU3RyaW5nOiA="
  "Capitalized Words: ", // "Q2FwaXRhbGl6ZWQgV29yZHM6IA=="
  "Contains 'world': ", // "Q29udGFpbnMgJ3dvcmxkJzog"
  "world", // "d29ybGQ="
];

// Functions using the decoded strings
function reverseString(str) {
  return str.split("").reverse().join("");
}

function capitalizeWords(str) {
  return str.replace(/\b\w/g, (char) => char.toUpperCase());
}

function checkStringIncludes(str, searchTerm) {
  return str.includes(searchTerm);
}

// Original and operations on the decoded message
let message = strings[6];
console.log(strings[8] + message);
console.log(strings[9] + reverseString(message));
console.log(strings[10] + capitalizeWords(message));
console.log(strings[11] + checkStringIncludes(message, strings[12]));
