// Decoded and renamed obfuscated array
let messages = [
  "split",
  "reverse",
  "join",
  "console",
  "Original String: ",
  "Reversed String: ",
  "Capitalized Words: ",
  "Contains 'world': "
];

// Function to reverse a string
function reverseString(string) {
  return string.split("").reverse().join("");
}

// Function to capitalize the first letter of each word in a string
function capitalizeWords(string) {
  return string.replace(/\b\w/g, (char) => char.toUpperCase());
}

// Function to check if a substring exists in a string
function containsSubstring(string, substring) {
  return string.includes(substring);
}

// Original string for demonstration
let originalString = "hello world from javascript";
console.log(messages[4] + originalString);
console.log(messages[5] + reverseString(originalString));
console.log(messages[6] + capitalizeWords(originalString));
console.log(messages[7] + containsSubstring(originalString, "world"));
