// Original Strings after Base64 decoding
const messages = [
  "split",
  "reverse",
  "join",
  "replace",
  "toUpperCase",
  "includes",
  "hello world from javascript",
  "log",
  "Original String: ",
  "Reversed String: ",
  "Capitalized Words: ",
  "Contains 'world': ",
  "world"
];

// Utility functions
function reverseString(input) {
  return input.split("").reverse().join("");
}

function capitalizeWords(input) {
  return input.replace(/\b\w/g, char => char.toUpperCase());
}

function stringIncludes(mainString, searchString) {
  return mainString.includes(searchString);
}

// String from decoded Base64
let originalStr = messages[6];

// Logging outputs
console.log(messages[8] + originalStr);
console.log(messages[9] + reverseString(originalStr));
console.log(messages[10] + capitalizeWords(originalStr));
console.log(messages[11] + stringIncludes(originalStr, messages[12]));
