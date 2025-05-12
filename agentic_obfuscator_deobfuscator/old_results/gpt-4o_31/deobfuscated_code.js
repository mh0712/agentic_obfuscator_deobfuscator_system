const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
function base64Decode(input) {
  const str = String(input).replace(/=+$/, "");
  let output = "";
  for (let bc = 0, bs, buffer, idx = 0; (buffer = str.charAt(idx++)); ~buffer && (bs = bc % 4 ? bs * 64 + buffer : buffer, bc++ % 4) ? output += String.fromCharCode(255 & bs >> (-2 * bc & 6)) : 0) {
    buffer = base64Chars.indexOf(buffer);
  }
  return output;
}

function customDecode(encodedStr) {
  const decodedStr = base64Decode(encodedStr);
  let output = "";
  for (let i = 0; i < decodedStr.length; i++) {
    output += "%" + ("00" + decodedStr.charCodeAt(i).toString(16)).slice(-2);
  }
  return decodeURIComponent(output);
}

class User {
  constructor(name, score = 0) {
    this.name = name;
    this.score = score;
  }

  addScore(points) {
    if (points > 0) {
      this.score += points;
      console.log(`${this.name} received ${points} points and now has ${this.score} points.`);
    } else {
      console.log("Invalid points");
    }
  }

  spendScore(points) {
    if (points > 0 && points <= this.score) {
      this.score -= points;
      console.log(`${this.name} spent ${points} points and now has ${this.score} points.`);
    } else if (points > this.score) {
      console.log("Not enough points");
    } else {
      console.log("Invalid points");
    }
  }

  transfer(points, user) {
    if (points > 0 && points <= this.score) {
      this.spendScore(points);
      user.addScore(points);
      console.log(`${this.name} transferred ${points} points to ${user.name}.`);
    } else {
      console.log("Transfer invalid");
    }
  }

  showScore() {
    console.log(`${this.name} has ${this.score} points`);
  }
}

class Leaderboard {
  constructor() {
    this.entries = [];
  }

  addEntry(entry) {
    this.entries.push(entry);
  }

  display() {
    if (this.entries.length === 0) {
      console.log("No entries yet.");
    } else {
      console.log("Leaderboard:");
      this.entries.forEach((entry, index) => {
        console.log(`${index + 1}. ${entry}`);
      });
    }
  }
}

const alice = new User("Alice", 1000);
const bob = new User("Bob", 500);
const leaderboard = new Leaderboard();

alice.addScore(200); 
alice.spendScore(150); 
setInterval(() => {
  alice.showScore();
}, 4000);

bob.addScore(300); 
alice.transfer(500, bob); 

leaderboard.addEntry("Sally");
leaderboard.addEntry("John");
leaderboard.addEntry("Alex");
leaderboard.addEntry("Mona");

alice.showScore();
bob.showScore();
leaderboard.display();

function availableFunction(input) {
  return input ? () => {} : () => {};
}
