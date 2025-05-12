function getRandomNumberInRange(min, max) {
  return Math.floor(Math.random() * getRangeDifference(min, max)) + min;
}

function getRangeDifference(min, max) {
  return max - min + 1;
}

function isEven(num) {
  return num % 2 === 0;
}

function generateNumber() {
  const number = getRandomNumberInRange(1, 100);
  console.log("Number generated:", number);

  if (isEven(number)) {
    console.log("It's even.");
  } else {
    console.log("It's odd.");
  }
}

generateNumber();

console.log("This is a hidden message!"); // This is a hidden message!