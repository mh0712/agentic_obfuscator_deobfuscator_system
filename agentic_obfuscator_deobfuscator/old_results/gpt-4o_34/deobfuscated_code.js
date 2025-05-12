// Decoded and cleaned string array
var stringsArray = [
  "withdraw",
  "function *()",
  "test",
  "chain",
  "SKaQa",
  "UmMXP",
  "balance",
  "log",
  "owner",
  " deposited $",
  ". New balance: $",
  "deposit",
  "sehkB",
  "Deposit amount must be greater than 0.",
  "withdraw",
  "NffUn",
  "CUBTF",
  "QOzRl",
  "NBORn",
  "vogue",
  "ewzOa",
  "ctvHC",
  "wxTWg",
  "IPlum",
  "SJFCz",
  "RlrRI",
  "swAVx",
  "Insufficient balance for withdrawal.",
  "JELlO",
  "Withdrawal amount must be greater than 0.",
  " withdraw $",
  "push",
  "transfer",
  "Nazwz",
  "VMWwP",
  "JtJbF",
  "eimSb",
  "Transfer failed. Insufficient balance or invalid amount.",
  "yhPzU",
  " transferred $",
  " to ",
  "showDetails",
  "'s Account: $",
  "record",
  "showHistory",
  "EnalG",
  "WEoNN",
  "wOUZh",
  "EwIdC",
  "DDgRS",
  "JJjwB",
  "CvFlm",
  "No transactions recorded.",
  "length",
  "Transaction History:",
  "forEach",
  "Alice",
  "Bob",
  "Alice deposited $200",
  "Alice withdrew $150",
  "Bob deposited $300",
  "sMYPG",
  "Alice transferred $500 to Bob",
  "EMKHv",
  "gger",
  "gtnk",
  "hVufl",
  "omCHz",
  "XRXdk",
  "counter",
  "HBiLL",
  "action",
  "lBrrp",
  "debug",
  "QwTeZ",
  "stateObject",
  "BCusv",
  "IXsFo",
  "BZqAC",
  "dYnCF",
  "mFFME",
  "string",
  "constructor",
  "while (true) {}",
  "YlUyx",
  "KvacD",
  "call",
  "pPtgk",
  "MziDo",
  "Edfrv",
  "JGesO",
  "xrMwN",
  "mAdhL",
  "kvBFg",
  "apply",
  "transactions",
  "vsJNU",
  "kzuEq",
  "DICzP",
  "KxTuh",
  "ZevVm",
  "tGXL",
  "init",
  "pTSrW",
  "input",
  "sGkeT",
  "EMYCE",
  "hhjVf",
  "fKeTx",
  "FqiRn",
  "wPjGn",
  "ZaBFd"
];

// Helper function to decode Base64 strings
function decodeBase64(string) {
  return decodeURIComponent(
    atob(string)
      .split("")
      .map(char => "%" + ("00" + char.charCodeAt(0).toString(16)).slice(-2))
      .join("")
  );
}

// Decoded strings using Base64
stringsArray = stringsArray.map(decodeBase64);

// Bank account class
class Account {
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
      console.log(`${this.owner} withdrew $${amount}. New balance: $${this.balance}`);
    } else if (amount > this.balance) {
      console.log("Insufficient balance for withdrawal.");
    } else {
      console.log("Withdrawal amount must be greater than 0.");
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

// Transaction record class
class TransactionRecord {
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

// Example usage
const aliceAccount = new Account("Alice", 1000);
const bobAccount = new Account("Bob", 500);
const transactionRecord = new TransactionRecord();

aliceAccount.deposit(200);
transactionRecord.record("Alice deposited $200");
aliceAccount.withdraw(150);
transactionRecord.record("Alice withdrew $150");
bobAccount.deposit(300);
transactionRecord.record("Bob deposited $300");
aliceAccount.transfer(500, bobAccount);
transactionRecord.record("Alice transferred $500 to Bob");

setInterval(() => {
  debuggerProtection();
}, 4000);

transactionRecord.record("Final transaction");
aliceAccount.showDetails();
bobAccount.showDetails();
transactionRecord.showHistory();

function debuggerProtection() {
  function test(value) {
    if (typeof value === "function") {
      return;
    } else {
      while (true) {}
    }
  }
}
