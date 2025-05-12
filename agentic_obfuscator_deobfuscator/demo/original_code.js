// BankAccount class to represent individual bank accounts
class BankAccount {
  constructor(owner, balance = 0) {
    this.owner = owner;
    this.balance = balance;
  }

  // Deposit money into the account
  deposit(amount) {
    if (amount > 0) {
      this.balance += amount;
      console.log(
        `${this.owner} deposited $${amount}. New balance: $${this.balance}`
      );
    } else {
      console.log("Deposit amount must be greater than 0.");
    }
  }

  // Withdraw money from the account
  withdraw(amount) {
    if (amount > 0 && amount <= this.balance) {
      this.balance -= amount;
      console.log(
        `${this.owner} withdrew $${amount}. New balance: $${this.balance}`
      );
    } else if (amount > this.balance) {
      console.log("Insufficient balance for withdrawal.");
    } else {
      console.log("Withdrawal amount must be greater than 0.");
    }
  }

  // Transfer money to another bank account
  transfer(amount, recipient) {
    if (amount > 0 && amount <= this.balance) {
      this.withdraw(amount);
      recipient.deposit(amount);
      console.log(
        `${this.owner} transferred $${amount} to ${recipient.owner}.`
      );
    } else {
      console.log("Transfer failed. Insufficient balance or invalid amount.");
    }
  }

  // Display account details
  showDetails() {
    console.log(`${this.owner}'s Account: $${this.balance}`);
  }
}

// TransactionHistory class to track transaction history
class TransactionHistory {
  constructor() {
    this.transactions = [];
  }

  // Record a transaction
  record(transaction) {
    this.transactions.push(transaction);
  }

  // Display all recorded transactions
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

// Create instances of BankAccount
const aliceAccount = new BankAccount("Alice", 1000);
const bobAccount = new BankAccount("Bob", 500);

// Create a TransactionHistory instance
const transactionHistory = new TransactionHistory();

// Perform some operations
aliceAccount.deposit(200);
aliceAccount.withdraw(150);
bobAccount.deposit(300);
aliceAccount.transfer(500, bobAccount);

// Record transactions
transactionHistory.record("Alice deposited $200");
transactionHistory.record("Alice withdrew $150");
transactionHistory.record("Bob deposited $300");
transactionHistory.record("Alice transferred $500 to Bob");

// Display account details
aliceAccount.showDetails();
bobAccount.showDetails();

// Display transaction history
transactionHistory.showHistory();
