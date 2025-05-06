// Define a list of Base64 encoded strings
var encodedStrings = [
  "YXBwbHk=", // 0: "apply"
  "ZnVuY3Rpb24gKlwoICpcKQ==", // 1: "function *\\( *\\)"
  "XCtcKyAqKD86XzB4KD86W2EtZjAtOV0pezQsNn18KD86XGJ8XGQpW2EtejAtOV17MSw0fSg/OlxifFxkKSk=", // 2: "\\+\\+(?:_0x(?:[a-f0-9]){4,6}|(?:\\b|\\d)[a-z0-9]{1,5})(?:\\]|\\())"
  "aW5pdA==", // 3: "init"
  "dGVzdA==", // 4: "test"
  "Y2hhaW4=", // 5: "chain"
  "aW5wdXQ=", // 6: "input"
  "b3duZXI=", // 7: "owner"
  "YmFsYW5jZQ==", // 8: "balance"
  "ZGVwb3NpdA==", // 9: "deposit"
  "bG9n", // 10: "log"
  "IGRlcG9zaXRlZCAk", // 11: " deposited $"
  "LiBOZXcgYmFsYW5jZTogJA==", // 12: ". New balance: $"
  "RGVwb3NpdCBhbW91bnQgbXVzdCBiZSBncmVhdGVyIHRoYW4gMC4=", // 13: "Deposit amount must be greater than 0."
  "d2l0aGRyYXc=", // 14: "withdraw"
  "IHdpdGhkcmV3ICQ=", // 15: " withdraw $"
  "SW5zdWZmaWNpZW50IGJhbGFuY2UgZm9yIHdpdGhkcmF3YWwu", // 16: "Insufficient balance for withdrawal."
  "V2l0aGRhddbalCBhbW91bnQgbXVzdCBiZSBncmVhdGVyIHRoYW4gMC4=", // 17: "Withdraw amount must be greater than 0."
  "dHJhbnNmZXI=", // 18: "transfer"
  "IHRyYW5zZmVycmVkICQ=", // 19: " transferred $"
  "IHRvIA==", // 20: " to "
  "VHJhbnNmZXIgZmFpbGVkLiBJbnN1ZmZpY2llbnQgYmFsYW5jZSBvciBpbnZhbGlkIGFtb3VudC4=", // 21: "Transfer failed. Insufficient balance or invalid amount."
  "c2hvd0RldGFpbHM=", // 22: "showDetails"
  "J3MgQWNjb3VudDogJA==", // 23: "'s Account: $"
  "dHJhbnNhY3Rpb25z", // 24: "transactions"
  "cmVjb3Jk", // 25: "record"
  "cHVzaA==", // 26: "push"
  "c2hvd0hpc3Rvcnk=", // 27: "showHistory"
  "bGVuZ3Ro", // 28: "length"
  "Tm8gdHJhbnNhY3Rpb25zIHJlY29yZGVkLg==", // 29: "No transactions recorded."
  "VHJhbnNhY3Rpb24gSGlzdG9yeTo=", // 30: "Transaction History:"
  "Zm9yRWFjaA==", // 31: "forEach"
  "QWxpY2U=", // 32: "Alice"
  "Qm9i", // 33: "Bob"
  "QWxpY2UgZGVwb3NpdGVkICQyMDA=", // 34: "Alice deposited $200"
  "QWxpY2Ugd2l0aGRyZXcgJDE1MA==", // 35: "Alice withdraw $150"
  "Qm9iIGRlcG9zaXRlZCAkMzAw", // 36: "Bob deposited $300"
  "QWxpY2UgdHJhbnNmZXJyZWQgJDUwMCB0byBCb2I=", // 37: "Alice transferred $500 to Bob"
  "c3RyaW5n", // 38: "string"
  "Y29uc3RydWN0b3I=", // 39: "constructor"
  "d2hpbGUgKHRydWUpIHt9", // 40: "while (true) {}"
  "Y291bnRlcg==", // 41: "counter"
  "ZGVidQ==", // 42: "debug"
  "Z2dlcg==", // 43: "gger"
  "Y2FsbA==", // 44: "call"
  "YWN0aW9u", // 45: "action"
  "c3RhdGVPYmplY3Q=" // 46: "stateObject"
];

// Function to decode base64 encoded strings
function decodeBase64(encoded) {
  return decodeURIComponent(Array.prototype.map.call(atob(encoded), function(c) {
    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
  }).join(''));
}

// Decode all encoded strings
var decodedStrings = encodedStrings.map(decodeBase64);

// Define the BankAccount class
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
      console.log("Deposit amount must be greater than 0.");
    }
  }

  withdraw(amount) {
    if (amount > 0 && amount <= this.balance) {
      this.balance -= amount;
      console.log(`${this.owner} withdraw $${amount}. New balance: $${this.balance}`);
    } else if (amount > this.balance) {
      console.log("Insufficient balance for withdrawal.");
    } else {
      console.log("Withdraw amount must be greater than 0.");
    }
  }

  transfer(amount, recipient) {
    if (amount > 0 && amount <= this.balance) {
      this.withdraw(amount);
      recipient.deposit(amount);
      console.log(`${this.owner} transferred $${amount} to ${recipient.owner}.`);
    } else {
      console.log("Transfer failed. Insufficient balance or invalid amount.");
    }
  }

  showDetails() {
    console.log(`${this.owner}'s Account: $${this.balance}`);
  }
}

// Define the TransactionHistory class
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

// Instantiate bank accounts and transaction history
const aliceAccount = new BankAccount("Alice", 1000);
const bobAccount = new BankAccount("Bob", 500);
const transactionHistory = new TransactionHistory();

// Perform some operations
aliceAccount.deposit(200);
aliceAccount.withdraw(150);
bobAccount.deposit(300);
aliceAccount.transfer(500, bobAccount);

// Record transactions
transactionHistory.record("Alice deposited $200");
transactionHistory.record("Alice withdraw $150");
transactionHistory.record("Bob deposited $300");
transactionHistory.record("Alice transferred $500 to Bob");

// Show account details and transaction history
aliceAccount.showDetails();
bobAccount.showDetails();
transactionHistory.showHistory();
