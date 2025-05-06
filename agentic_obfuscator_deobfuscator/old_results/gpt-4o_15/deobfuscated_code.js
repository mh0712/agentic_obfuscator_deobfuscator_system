// Functions to manipulate strings
function reverseString(inputString) {
  return inputString.split("").reverse().join("");
}

function capitalizeWords(inputString) {
  return inputString.replace(/\b\w/g, (match) => match.toUpperCase());
}

function containsSubstring(mainString, substring) {
  return mainString.includes(substring);
}

// The original string to process
let myString = "hello world from javascript";

// Logging results from string manipulation
console.log("Original String: " + myString);
console.log("Reversed String: " + reverseString(myString));
console.log("Capitalized Words: " + capitalizeWords(myString));
console.log("Contains 'world': " + containsSubstring(myString, "world"));
