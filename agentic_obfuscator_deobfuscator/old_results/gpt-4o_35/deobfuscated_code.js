const decodedStrings = [
  "Transaction History:",
  "push",
  "length",
  "showDetails",
  "Balance",
  "forEach",
  "Alice",
  "Bob",
  "Alice deposited $200",
  "Alice withdraw $150",
  "Bob deposited $300",
  "Alice transferred $500 to Bob",
  "owner",
  "balance",
  "deposit",
  "log",
  " deposited $",
  ". New balance: $",
  "Deposit amount must be greater than 0.",
  "withdraw",
  "Insufficient balance for withdrawal.",
  "Withdrawal amount must be greater than 0.",
  "Transfer failed. Insufficient balance or invalid amount.",
  "showHistory",
  "No transactions recorded.",
];

// Replacing the obfuscated array and decoding function
function decodedString(index) {
  return decodedStrings[index];
}

class Account {
  constructor(owner, balance = 0) {
    this.owner = owner;
    this.balance = balance;
  }

  deposit(amount) {
    if (amount > 0) {
      this.balance += amount;
      console.log(this.owner + " deposited $" + amount + ". New balance: $" + this.balance);
    } else {
      console.log("Deposit amount must be greater than 0.");
    }
  }

  withdraw(amount) {
    if (amount > 0 && amount <= this.balance) {
      this.balance -= amount;
      console.log(this.owner + " withdraw $" + amount + ". New balance: $" + this.balance);
    } else if (amount > this.balance) {
      console.log("Insufficient balance for withdrawal.");
    } else {
      console.log("Withdrawal amount must be greater than 0.");
    }
  }

  transfer(amount, targetAccount) {
    if (amount > 0 && amount <= this.balance) {
      this.withdraw(amount);
      targetAccount.deposit(amount);
      console.log(this.owner + " transferred $" + amount + " to " + targetAccount.owner + ".");
    } else {
      console.log("Transfer failed. Insufficient balance or invalid amount.");
    }
  }

  showBalance() {
    console.log(this.owner + decodedString(16) + this.balance);
  }
}

class TransactionHistory {
  constructor() {
    this.transactions = [];
  }

  push(transaction) {
    this.transactions.push(transaction);
  }

  log() {
    if (this.transactions.length === 0) {
      console.log(decodedString(24));
    } else {
      console.log(decodedString(0));
      this.transactions.forEach((transaction, index) => {
        console.log((index + 1) + ". " + transaction);
      });
    }
  }
}

// Sample usage
const aliceAccount = new Account("Alice", 1000);
const bobAccount = new Account("Bob", 500);
const transactionHistory = new TransactionHistory();

aliceAccount.deposit(200);
aliceAccount.withdraw(150);
bobAccount.deposit(300);
aliceAccount.transfer(500, bobAccount);
transactionHistory.push("Alice deposited $200");
transactionHistory.push("Alice withdraw $150");
transactionHistory.push("Bob deposited $300");
transactionHistory.push("Alice transferred $500 to Bob");

aliceAccount.showBalance();
bobAccount.showBalance();
transactionHistory.log();
