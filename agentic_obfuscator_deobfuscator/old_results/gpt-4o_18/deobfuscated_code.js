// Decoded strings and meaningful names
let encodedStrings = [
  "c3BsaXQ=", // split
  "cmV2ZXJzZQ==", // reverse
  "am9pbg==", // join
  "cmVwbGFjZQ==", // replace
  "dG9VcHBlckNhc2U=", // toUpperCase
  "aW5jbHVkZXM=", // includes
  "aGVsbG8gd29ybGQgZnJvbSBqYXZhc2NyaXB0", // hello world from javascript
  "bG9n", // log
  "T3JpZ2luYWwgU3RyaW5nOiA=", // Original String: 
  "UmV2ZXJzZWQgU3RyaW5nOiA=", // Reversed String: 
  "Q2FwaXRhbGl6ZWQgV29yZHM6IA==", // Capitalized Words:
  "Q29udGFpbnMgJ3dvcmxkJzog", // Contains 'world': 
  "d29ybGQ=", // world
];

function decodeBase64(index) {
  return atob(encodedStrings[index]);
}

function splitReverseJoin(str) {
  return str.split("").reverse().join("");
}

function capitalizeWords(str) {
  return str.replace(/\b\w/g, char => char.toUpperCase());
}

function replaceIncludes(str, search) {
  return str.includes(search);
}

let originalString = decodeBase64(6); // Decoded hello world from javascript

// Output the transformations
console.log(decodeBase64(8) + originalString);

let reversedString = splitReverseJoin(originalString);
console.log(decodeBase64(9) + reversedString);

let capitalizedWordsString = capitalizeWords(originalString);
console.log(decodeBase64(10) + capitalizedWordsString);

let containsWorld = replaceIncludes(originalString, decodeBase64(12));
console.log(decodeBase64(11) + containsWorld);
