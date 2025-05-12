class Account {
  constructor(owner, balance = 0) {
    this.owner = owner;
    this.balance = balance;
  }

  deposit(amount) {
    if (amount > 0) {
      this.balance += amount;
      console.log(`Deposited $${amount}. New balance: $${this.balance}`);
    } else {
      console.log("Deposit amount must be greater than 0.");
    }
  }

  withdraw(amount) {
    if (amount > 0 && amount <= this.balance) {
      this.balance -= amount;
      console.log(`Withdrew $${amount}. New balance: $${this.balance}`);
    } else if (amount > this.balance) {
      console.log(`Insufficient balance for withdrawal.`);
    } else {
      console.log("Withdrawal amount must be greater than 0.");
    }
  }

  transfer(amount, recipientAccount) {
    if (amount > 0 && amount <= this.balance) {
      this.withdraw(amount);
      recipientAccount.deposit(amount);
      console.log(
        `${this.owner} transferred $${amount} to ${recipientAccount.owner}.`
      );
    } else {
      console.log("Transfer failed. Insufficient balance or invalid amount.");
    }
  }

  showBalance() {
    console.log(`${this.owner} balance: $${this.balance}`);
  }
}

class TransactionHistory {
  constructor() {
    this.transactions = [];
  }

  record(transaction) {
    this.transactions.push(transaction);
  }

  showDetails() {
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

// Example usage
const aliceAccount = new Account("Alice", 1000);
const bobAccount = new Account("Bob", 500);
const transactionHistory = new TransactionHistory();

aliceAccount.deposit(200);
aliceAccount.withdraw(150);
bobAccount.deposit(300);
aliceAccount.transfer(500, bobAccount);

transactionHistory.record("Alice deposited $200");
transactionHistory.record("Alice withdrew $150");
transactionHistory.record("Bob deposited $300");
transactionHistory.record("Alice transferred $500 to Bob");

aliceAccount.showBalance();
bobAccount.showBalance();
transactionHistory.showDetails();
