function getRandomNumber(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function isEven(num) {
  return num % 2 === 0;
}

function execute() {
  const randomNum = getRandomNumber(1, 100);
  console.log("Number generated:", randomNum);

  if (isEven(randomNum)) {
    console.log("It's even.");
  } else {
    console.log("It's odd.");
  }
}

function decodeBase64String(encodedStr) {
  return atob(encodedStr);
}

execute();

console.log("This is a hidden message!");