// Array containing Base64-encoded strings.
var base64Strings = [
  "am5veVE=", "ZnVuY3Rpb24gKlwoICpcKQ==", "dGVzdA==", "Y2hhaW4=", "S0thUWE=", 
  "VW1NWFA=", "YmFsYW5jZQ==", "bG9n", "b3duZXI=", "IGRlcG9zaXRlZCAk", 
  "LiBOZXcgYmFsYW5jZTogJA==", "ZGVwb3NpdA==", "c2Voa2I=", 
  "RGVwb3NpdCBhbW91bnQgbXVzdCBiZSBncmVhdGVyIHRoYW4gMC4=", "d2l0aGRyYXc=", 
  "TmZmVW4=", "Q1VCVEY=", "UU96Umw=", "TkJPUm4=", "dm9ncGU=", 
  "ZXd6T2E=", "Y3R2SEM=", "d3hUV2c=", "SVBsdW0=", "U0pGQ3o=", 
  "UmxyUkk=", "c3dBVng=", "SW5zdWZmaWNpZW50IGJhbGFuY2UgZm9yIHdpdGhkcmF3YWwu", 
  "SkVMbE8=", "V2l0aGRyYXdhbCBhbW91bnQgbXVzdCBiZSBncmVhdGVyIHRoYW4gMC4=", 
  "IHdpdGhkcmV3ICQ=", "cHVzaA==", "dHJhbnNmZXI=", "TmF6d3o=", 
  "Vk1Xd1A=", "SnRKYkY=", "ZWltU2I=", "VHJhbnNmZXIgZmFpbGVkLiBJbnN1ZmZpY2llbnQgYmFsYW5jZSBvciBpbnZhbGlkIGFtb3VudC4=", 
  "eWhQelU=", "IHRyYW5zZmVycmVkICQ=", "IHRvIA==", "c2hvd0RldGFpbHM=", 
  "J3MgQWNjb3VudDogJA==", "cmVjb3Jk", "c2hvd0hpc3Rvcnk=", "RW5hbUc=", 
  "V0VvTk4=", "d09VWmg=", "RXdJZEM=", "RERnUlM=", "Skpqd0I=", 
  "Q3ZGbG0=", "Tm8gdHJhbnNhY3Rpb25zIHJlY29yZGVkLg==", "bGVuZ3Ro", 
  "VHJhbnNhY3Rpb24gSGlzdG9yeTo=", "Zm9yRWFjaA==", "QWxpY2U=", "Qm9i", 
  "QWxpY2UgZGVwb3NpdGVkICQyMDA=", "QWxpY2Ugd2l0aGRyZXcgJDE1MA==", 
  "Qm9iIGRlcG9zaXRlZCAkMzAw", "c01ZUEc=", 
  "QWxpY2UgdHJhbnNmZXJyZWQgJDUwMCB0byBCb2I=", "RU1LSHY=", "Z2dlcg==", 
  "Z3RuZGs=", "aFZ1Zmw=", "b21DSHo=", "WFJYZGs=", "Y291bnRlcg==", 
  "SEJpTEw=", "YWN0aW9u", "bEJycnA=", "ZGVidQ==", "UXdUZVo=", 
  "c3RhdGVPYmplY3Q=", "QkN1c3Y=", "SVhzRm8=", "QlpxQUM=", "ZFluQ0Y=", 
  "bUZGTUU=", "c3RyaW5n", "Y29uc3RydWN0b3I=", "d2hpbGUgKHRydWUpIHt9", 
  "WWxVeXg=", "S3dhY0Q=", "Y2FsbA==", "cFB0Z2s=", "TXppRG8=", "RWRmcnY=", 
  "Skdlc08=", "eHJNd04=", "bUFkaEw=", "a3ZCRmc=", "YXBwbHk=", 
  "dHJhbnNhY3Rpb25z", "dnNKTlU=", "a3p1RXE=", "RElDelA=", "S3hUdWg=", 
  "XCtcKyAqKD86XzB4KD86W2EtZjAtOV0pezQsNn18KD86XGJ8XGQpW2EtejAtOV17MSw0fSg/OlxifFxkKSk=", 
  "WmVWbUw=", "dEdYTEM=", "aW5pdA==", "cFRTclc=", "aW5wdXQ=", "c0drZVQ=", 
  "RU1ZQ1E=", "aHhqVmY=", "ZktlVHg=", "RnFpUm4=", "d1BqR24=", 
  "WmFCRmQ="
];

// Base64 decode a string.
function decodeBase64(encoded) {
  return decodeURIComponent(
    atob(encoded)
      .split('')
      .map((char) => '%' + ('00' + char.charCodeAt(0).toString(16)).slice(-2))
      .join('')
  );
}

// Decoded strings stored according to index shifts.
var stringOffset = 426; // Decoding stringOffset based on modulation
var decodedStrings = [];
for (var i = 0; i < base64Strings.length; i++) {
  decodedStrings[i] = decodeBase64(base64Strings[(i + stringOffset) % base64Strings.length]);
}

// Example utility functions
function logDetails() {
  console.log(decodedStrings[7] + decodedStrings[9]);
}

// Example class demonstrating object-oriented concepts
class Account {
  constructor(owner, initialBalance = 0) {
    this.owner = owner;
    this.balance = initialBalance;
  }

  deposit(amount) {
    if (amount > 0) {
      this.balance += amount;
      console.log(this.owner + ' deposited $' + amount + '. New balance: $' + this.balance);
    } else {
      console.log('Insufficient balance for withdrawal.');
    }
  }

  withdraw(amount) {
    if (amount > 0 && amount <= this.balance) {
      this.balance -= amount;
      console.log(this.owner + ' withdrew $' + amount + '. New balance: $' + this.balance);
    } else if (amount > this.balance) {
      console.log('Insufficient balance for withdrawal.');
    } else {
      console.log('Invalid transaction.');
    }
  }

  transfer(amount, targetAccount) {
    if (amount > 0 && amount <= this.balance) {
      this.withdraw(amount);
      targetAccount.deposit(amount);
      console.log(
        this.owner + ' transferred $' + amount + ' to ' + targetAccount.owner + '.'
      );
    } else {
      console.log('Transfer failed. Insufficient balance or invalid amount.');
    }
  }

  showBalance() {
    console.log(this.owner + "'s balance is: $" + this.balance);
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
        console.log(index + 1 + ". " + transaction);
      });
    }
  }
}

// Sample usage
const aliceAccount = new Account('Alice', 1000);
const bobAccount = new Account('Bob', 500);
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
transactionHistory.showHistory();
