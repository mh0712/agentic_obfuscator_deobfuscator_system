const decodedStrings = [
  "a3prZlY=",
  "RVJSUWM=",
  "V0FMdEg=",
  "R1ZWpVA=",
  "UXpBYmc=",
  "UkxaQ=",
  "d29EZW8=",
  "VjRwZD3o=",
  "cWh5aTo=",
  "Y3ZQWF0=",
  "cWF5eW1n",
  "YXZB==",
  "YWk5ZW9y",
  "MnpCZHM=",
  "RXhhQUg=",
  "VHlahDEYGlenDWYt0To=",
  "Ymp0Um=",
  "R1dsdxZHubb1pnXWKnaZWSmYg=",
  "dkxbZlY=",
  "VmlucXg=",
  "cFZwYWlv",
  "VnZjZXIE=",
  "V21saUVLM=",
  "QkRjPls=",
  "aWVXPSU=",
  "YWdfVkM=",
  "V0ZY",
];

function getDecodedString(index) {
  return decodedStrings[index];
}

class Account {
  constructor(name, initialBalance = 0) {
    this.name = name;
    this.balance = initialBalance;
  }

  deposit(amount) {
    if (amount > 0) {
      this.balance += amount;
      console.log(
        `Deposited ${amount} to ${this.name}. New balance: ${this.balance}`
      );
    } else {
      console.log("Deposit amount must be greater than zero.");
    }
  }

  withdraw(amount) {
    if (amount > 0 && amount <= this.balance) {
      this.balance -= amount;
      console.log(
        `Withdrawn ${amount} from ${this.name}. New balance: ${this.balance}`
      );
    } else {
      console.log("Invalid withdrawal amount.");
    }
  }

  transfer(amount, recipient) {
    if (amount > 0 && amount <= this.balance) {
      this.withdraw(amount);
      recipient.deposit(amount);
      console.log(
        `Transferred ${amount} from ${this.name} to ${recipient.name}.`
      );
    } else {
      console.log("Invalid transfer amount.");
    }
  }

  getBalance() {
    console.log(`${this.name} balance: ${this.balance}`);
  }
}

class Bank {
  constructor() {
    this.accounts = [];
  }

  addAccount(account) {
    this.accounts.push(account);
  }

  listAccounts() {
    if (this.accounts.length === 0) {
      console.log("No accounts available.");
    } else {
      console.log("Available Accounts:");
      this.accounts.forEach((account, index) => {
        console.log(`${index + 1}. ${account.name}`);
      });
    }
  }
}

setInterval(() => {
  console.log("Running periodic check...");
}, 4000);

// Example Usage
const account1 = new Account("John Doe", 1000);
const account2 = new Account("Jane Doe", 500);
const bank = new Bank();

account1.deposit(200);
account1.withdraw(150);
account2.deposit(300);
account1.transfer(100, account2);
bank.addAccount("Savings Account");
bank.listAccounts();
account1.getBalance();
account2.getBalance();
