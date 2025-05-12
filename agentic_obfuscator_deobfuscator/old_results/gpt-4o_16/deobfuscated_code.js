// Decoded array of strings
var decodedStrings = [
  "Q29udGFpbnMgdGhpcyBnb3Q=",
  "d29ybGQ=",
  "c3VzcQ==",
  "cmV2ZXJzZSBEZWZpbml0ZWx5",
  "YWxpbG1n",
  "cmV2ZXJzIFIjZ1NlcnZpY2U=",
  "dG9iZWwgY2lya2l0",
  "aWdqbXQ=",
  "aGVsbG8gd29ybGQgd29ya2luZw==",
  "bG9nZ2lu",
  "T3VyIG54IGlz",
  "UmV2ZXJzaW5nIGVuZ2luZWUgUHJv",
  "Q2ZyZzo="
];

// Function to decode Base64 strings
function decodeBase64(encodedString) {
  return decodeURIComponent(
    atob(encodedString)
      .split("")
      .map(function (c) {
        return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
      })
      .join("")
  );
}

// Reversed meaningful functions and variables
function reverseString(inputString) {
  return inputString.split("").reverse().join("");
}

function capitalizeWords(inputString) {
  return inputString.replace(/\b\w/g, function (match) {
    return match.toUpperCase();
  });
}

function containsSubstring(fullString, substring) {
  return fullString.includes(substring);
}

let myString = decodeBase64(decodedStrings[8]);

console.log("Decoded String: " + myString);
console.log("Reversed String: " + reverseString(myString));
console.log("Capitalized Words: " + capitalizeWords(myString));
console.log("Contains 'log': " + containsSubstring(myString, "log"));