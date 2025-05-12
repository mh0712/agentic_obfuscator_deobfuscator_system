class BankAccount {
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
      console.log("Withdraw amount must be greater than 0.");
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

  showDetails() {
    console.log(this.owner + "'s Account: $" + this.balance);
  }
}

class TransactionHistory {
  constructor() {
    this.transactions = [];
  }

  record(transaction) {
    this.transactions.push(transaction);
  }

  showHistory() {
    if (this.transactions.length === 0) {
      console.log("No transactions recorded.");
    } else {
      console.log("Transaction History:");
      this.transactions.forEach((transaction, index) => {
        console.log((index + 1) + ". " + transaction);
      });
    }
  }
}

const aliceAccount = new BankAccount("Alice", 1000);
const bobAccount = new BankAccount("Bob", 500);
const transactionHistory = new TransactionHistory();

aliceAccount.deposit(200);
aliceAccount.withdraw(150);
bobAccount.deposit(300);
aliceAccount.transfer(500, bobAccount);
transactionHistory.record("Alice deposited $200");
transactionHistory.record("Alice withdraw $150");
setInterval(function () {
  // empty function removed from here
}, 4000);
transactionHistory.record("Bob deposited $300");
transactionHistory.record("Alice transferred $500 to Bob");
aliceAccount.showDetails();
bobAccount.showDetails();
transactionHistory.showHistory();
