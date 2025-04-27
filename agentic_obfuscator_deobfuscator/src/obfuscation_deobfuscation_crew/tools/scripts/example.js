function getRandomNumber(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function isEven(number) {
  return number % 2 === 0;
}

function main() {
  const randomNumber = getRandomNumber(1, 100);
  console.log("Generated number:", randomNumber);

  if (isEven(randomNumber)) {
    console.log("The number is even.");
  } else {
    console.log("The number is odd.");
  }
}

main();
