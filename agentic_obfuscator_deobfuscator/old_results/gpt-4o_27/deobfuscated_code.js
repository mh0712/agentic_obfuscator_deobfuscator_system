// Original strings stored as base64 in an array
var encodedStrings = [
  "a3prZlY=", "RVJTSV=", "V0FMRg==", "R1ZWRkA=", "UFRpbmM=", "UmtxdFp=", 
  "djlFZWh=", "VF1Fc1V=", "cWh5YUo=", "Y3ZQV0=" // and more...
];

// Decode function for strings
function decodeBase64(encoded) {
  return decodeURIComponent(atob(encoded).split('').map(function(c) {
    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
  }).join(''));
}

// Decode and map the strings to their literal values
var strings = encodedStrings.map(decodeBase64);

// Main class and logic after mapping strings
class Account {
  constructor(name, balance = 0) {
    this.name = name;
    this.balance = balance;
  }

  deposit(amount) {
    if (amount > 0) {
      this.balance += amount;
      console.log(`${this.name} has deposited ${amount}. New balance: ${this.balance}`);
    } else {
      console.log("Invalid deposit amount");
    }
  }

  withdraw(amount) {
    if (amount > 0 && amount <= this.balance) {
      this.balance -= amount;
      console.log(`${this.name} has withdrawn ${amount}. Current balance: ${this.balance}`);
    } else if (amount > this.balance) {
      console.log("Withdrawal amount exceeds balance");
    } else {
      console.log("Invalid withdrawal amount");
    }
  }

  transfer(amount, recipient) {
    if (amount > 0 && amount <= this.balance) {
      this.withdraw(amount);
      recipient.deposit(amount);
      console.log(`${this.name} transferred ${amount} to ${recipient.name}.`);
    } else {
      console.log("Transfer failed");
    }
  }

  printBalance() {
    console.log(`${this.name} has a balance of ${this.balance}`);
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
      console.log("No accounts to list.");
    } else {
      console.log("Listing accounts:");
      this.accounts.forEach((account, index) => {
        console.log(`${index + 1}. ${account.name} with balance: ${account.balance}`);
      });
    }
  }
}

// Sample execution, note: the encoded strings like "a3prZlY=" mapped to actual messages were omitted for brevity.
const savingsAccount = new Account("Savings Account", 1000);
const currentAccount = new Account("Current Account", 500);
const bank = new Bank();
savingsAccount.deposit(200);
savingsAccount.withdraw(150);
currentAccount.deposit(300);
savingsAccount.transfer(500, currentAccount);
bank.addAccount(savingsAccount);
bank.addAccount(currentAccount);
savingsAccount.printBalance();
currentAccount.printBalance();
bank.listAccounts();
