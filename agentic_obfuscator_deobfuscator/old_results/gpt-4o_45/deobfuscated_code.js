// Deobfuscated and cleaned code based on the provided techniques

// Removed debug protection logic
// Step 1: I identified the debug protection functions and mechanisms, such as the function _0x4047d5 and other similar constructs, and neutralized them while preserving functionality.

class BankAccount {
  constructor(ownerName, initialBalance = 0) {
    this.owner = ownerName;
    this.balance = initialBalance;
  }

  deposit(amount) {
    if (amount > 0) {
      this.balance += amount;
      console.log(`${this.owner} deposited ${amount}. New balance: ${this.balance}`);
    } else {
      console.log("Deposit amount must be positive.");
    }
  }

  withdraw(amount) {
    if (amount > 0 && amount <= this.balance) {
      this.balance -= amount;
      console.log(`${this.owner} withdrew ${amount}. New balance: ${this.balance}`);
    } else if (amount > this.balance) {
      console.log("Insufficient funds.");
    } else {
      console.log("Withdrawal amount must be positive.");
    }
  }

  transfer(amount, recipient) {
    if (amount > 0 && amount <= this.balance) {
      this.withdraw(amount);
      recipient.deposit(amount);
      console.log(`${this.owner} transferred ${amount} to ${recipient.owner}.`);
    } else {
      console.log("Transfer could not be completed.");
    }
  }

  printBalance() {
    console.log(`${this.owner} has a balance of ${this.balance}`);
  }
}

class TransactionHistory {
  constructor() {
    this.transactions = [];
  }

  addTransaction(transaction) {
    this.transactions.push(transaction);
  }

  printTransactions() {
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

const aliceAccount = new BankAccount("Alice", 1000);
const bobAccount = new BankAccount("Bob", 500);
const transactionHistory = new TransactionHistory();

aliceAccount.deposit(200);
aliceAccount.withdraw(150);
bobAccount.deposit(300);
aliceAccount.transfer(500, bobAccount);

transactionHistory.addTransaction("Alice deposited 200.");
transactionHistory.addTransaction("Alice withdrew 150.");
transactionHistory.addTransaction("Bob deposited 300.");
transactionHistory.addTransaction("Alice transferred 500 to Bob.");

aliceAccount.printBalance();
bobAccount.printBalance();
transactionHistory.printTransactions();
