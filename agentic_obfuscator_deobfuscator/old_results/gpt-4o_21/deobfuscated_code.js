// Original array of strings used for encoded property access
var stringsArray = [
  "split", "reverse", "join", "replace", "toUpperCase",
  "includes", "hello world from javascript", "log",
  "Original String: ", "Reversed String: ", "Capitalized Words: ",
  "Contains 'world': ", "world"
];

// Decoder function to get the actual string from the array
function getString(index) {
  return stringsArray[index];
}

// Function to reverse a given string
function reverseString(inputString) {
  return inputString.split("").reverse().join("");
}

// Function to capitalize the first letter of each word in a string
function capitalizeWords(inputString) {
  return inputString.replace(/\b\w/g, (match) => match.toUpperCase());
}

// Function to check if a string contains a given substring
function containsSubstring(fullString, substring) {
  return fullString.includes(substring);
}

// Main program logic
let myString = getString(6); // "hello world from javascript"
console.log(getString(8) + myString);
console.log(getString(9) + reverseString(myString));
console.log(getString(10) + capitalizeWords(myString));
console.log(getString(11) + containsSubstring(myString, getString(12)));
