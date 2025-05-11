// This function is used to decode Base64 encoded strings.
function decodeBase64(encodedString) {
  return decodeURIComponent(Array.prototype.map.call(atob(encodedString), function(c) {
    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
  }).join(''));
}

// Decoded strings array using Base64 decoding.
var strings = [
  "apply", // YXBwbHk=
  "function *\(\ \*\)", // ZnVuY3Rpb24gKlwoICpcKQ==
  "\\+\\ *\(?:_0x(?:[a-f0-9]){4,6}){4}|(?:\\b|\\d)+", // XCtcKyAqKD86XzB4KD86W2EtZjAtOV0pezQsNn18KD86XGJ8XGQpW2EtejAtOV17MSw0fSg/OlxifFxkKSk=
  "init", // aW5pdA==
  "test", // dGVzdA==
  "chain", // Y2hhaW4=
  "input", // aW5wdXQ=
  "owner", // b3duZXI=
  "balance", // YmFsYW5jZQ==
  "deposit", // ZGVwb3NpdA==
  "log", // bG9n
  " deposited $", // IGRlcG9zaXRlZCAk
  ". New balance: $", // LiBOZXcgYmFsYW5jZTogJA==
  "Deposit amount must be greater than 0.", // RGVwb3NpdCBhbW91bnQgbXVzdCBiZSBncmVhdGVyIHRoYW4gMC4=
  "withdraw", // d2l0aGRhcg==
  " withdrew $", // IHdpdGhkcmV3ICQ=
  "Insufficient balance for withdrawal.", // SW5zdWZmaWN0IGJhbGFuY2UgZm9yIHdpdGhkcmF3YWwu
  "Withdrawal amount must be greater than 0.", // V2l0aGRhd2FsIGFtb3VudCBtdXN0IGJlIGdyZWF0ZXIgdGhhbiAwLg==
  "transfer", // dHJhbnNmZXI=
  " transferred $", // IHRyYW5zZmVycmVkICQ=
  " to ", // IHRvIA==
  "Transfer failed. Insufficient balance or invalid amount.", // VHJhbnNmZXIgZmFpbGVkLiBJbnN1ZmZpY2llbnQgYmFsYW5jZSBvciBpbnZhbGlkIGFtb3VudC4=
  "showDetails", // c2hvd0RldGFpbHM=
  "'s Account: $", // J3MgQWNjb3VudDogJA==
  "transactions", // dHJhbnNhY3Rpb25z
  "record", // cmVjb3Jk
  "push", // cHVzaA==
  "showHistory", // c2hvd0hpc3Rvcnk=
  "length", // bGVuZ3Ro
  "No transactions recorded.", // Tm8gdHJhbnNhY3Rpb25zIHJlY29yZGVkLg==
  "Transaction History:", // VHJhbnNhY3Rpb24gSGlzdG9yeTo=
  "forEach", // Zm9yRWFjaA==
  "Alice", // QWxpY2U=
  "Bob", // Qm9i
  "Alice deposited $200", // QWxpY2UgZGVwb3NpdGVkICQyMDA=
  "Alice withdrew $150", // QWxpY2Ugd2l0aGRyZXcgJDE1MA==
  "Bob deposited $300", // Qm9iIGRlcG9zaXRlZCAkMzAw
  "Alice transferred $500 to Bob", // QWxpY2UgdHJhbnNmZXJyZWQgJDUwMCB0byBCb2I=
  "string", // c3RyaW5n
  "constructor", // Y29uc3RydWN0b3I=
  "while (true) {}", // d2hpbGUgKHRydWUpIHt9
  "counter", // Y291bnRlcg==
  "debug", // ZGVidQ==
  "ggeg", // Z2dlcg==
  "call", // Y2FsbA==
  "action", // YWN0aW9u
  "stateObject" // c3RhdGVPYmplY3Q=
];

// Removing debug protection logic from the code.
function safeFunction(func, context) {
  return function() {
    if (context) {
      let result = context.apply(func, arguments);
      context = null;
      return result;
    }
  }
}

// BankAccount class definition using clear variable names
class BankAccount {
  constructor(owner, initialBalance = 0) {
    this.owner = owner;
    this.balance = initialBalance;
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
      console.log(`${this.owner} withdrew $${amount}. New balance: $${this.balance}`);
    } else if (amount > this.balance) {
      console.log("Insufficient balance for withdrawal.");
    } else {
      console.log("Withdrawal amount must be greater than 0.");
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

// TransactionHistory class to manage and show transaction history
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

// Creating instances for Alice and Bob
const aliceAccount = new BankAccount("Alice", 1000);
const bobAccount = new BankAccount("Bob", 500);
const transactionHistory = new TransactionHistory();

// Performing transactions
aliceAccount.deposit(200);
aliceAccount.withdraw(150);
bobAccount.deposit(300);
aliceAccount.transfer(500, bobAccount);

// Recording transactions
transactionHistory.record("Alice deposited $200");
transactionHistory.record("Alice withdrew $150");
setInterval(() => { safeFunction(() => {})(); }, 4000); // Removed `debugger`
transactionHistory.record("Bob deposited $300");
transactionHistory.record("Alice transferred $500 to Bob");

// Showing account details and transactions
aliceAccount.showDetails();
bobAccount.showDetails();
transactionHistory.showHistory();
