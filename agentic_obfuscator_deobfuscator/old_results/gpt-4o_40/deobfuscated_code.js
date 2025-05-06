// A human-readable and semantically equivalent version of the original code.

class BankAccount {
  constructor(owner, balance = 0) {
    this.owner = owner;
    this.balance = balance;
  }

  deposit(amount) {
    if (amount > 0) {
      this.balance += amount;
      console.log(`${this.owner} deposited $${amount}. New balance: $${this.balance}`);
    } else {
      console.log("Deposit amount must be positive.");
    }
  }

  withdraw(amount) {
    if (amount > 0 && amount <= this.balance) {
      this.balance -= amount;
      console.log(`${this.owner} withdrew $${amount}. New balance: $${this.balance}`);
    } else if (amount > this.balance) {
      console.log("Insufficient balance for withdrawal.");
    } else {
      console.log("Withdrawal amount must be positive.");
    }
  }

  transfer(amount, recipientAccount) {
    if (amount > 0 && amount <= this.balance) {
      this.withdraw(amount);
      recipientAccount.deposit(amount);
      console.log(`${this.owner} transferred $${amount} to ${recipientAccount.owner}.`);
    } else {
      console.log("Transfer failed. Insufficient balance or invalid amount.");
    }
  }

  showDetails() {
    console.log(`${this.owner}'s Account: $${this.balance}`);
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
        console.log(`${index + 1}. ${transaction}`);
      });
    }
  }
}

// Create bank accounts for Alice and Bob
const aliceAccount = new BankAccount("Alice", 1000);
const bobAccount = new BankAccount("Bob", 500);

// Create a transaction history
const transactionHistory = new TransactionHistory();

// Perform transactions
aliceAccount.deposit(200);
aliceAccount.withdraw(150);
bobAccount.deposit(300);
aliceAccount.transfer(500, bobAccount);

// Record transactions in history
transactionHistory.record("Alice deposited $200");
transactionHistory.record("Alice withdrew $150");

// Show account details and transactions
aliceAccount.showDetails();
bobAccount.showDetails();
transactionHistory.showHistory();
