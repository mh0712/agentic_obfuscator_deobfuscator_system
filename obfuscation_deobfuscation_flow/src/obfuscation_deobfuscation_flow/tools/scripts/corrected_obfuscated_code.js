
function z17c(i2K, J9j) {
  return Math.floor(Math.random() * (J9j - i2K + 1)) + i2K;
}

function o11Z(U7x) {
  return U7x % 2 === 0;
}

function w2Yx() {
  const sH6C = z17c(1, 100);
  console.log("Generated number:", sH6C);

  if (o11Z(sH6C)) {
    console.log("The number is even.");
  } else {
    console.log("The number is odd.");
  }
}

w2Yx();