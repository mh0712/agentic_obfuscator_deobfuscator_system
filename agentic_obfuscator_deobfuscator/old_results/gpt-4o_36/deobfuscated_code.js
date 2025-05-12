// Define the decoder function to resolve obfuscated string array values
function decode(index) {
  const base64Strings = [
    "ZGVidQ==",
    "c3RhdGVPYmplY3Q=",
    "TldZam0=",
    "Y0N0cEw=",
    "Y29uc3RydWN0b3I=",
    "d2hpbGUgKHRydWUpIHt9",
    "TkFZbXM=",
    "YUlndlk=",
    "UVhDcUo=",
    "Z2dlcg==",
    "Y2FsbA==",
    "YWN0aW9u",
    "aG1DdHY=",
    "bUpxbVE=",
    "TGJBdGk=",
    "YXBwbHk=",
    "\\+\\*\\*\\+\\((\\?\\_0\\x0y\\(\\?\\[a-f0-9]{4}\\)|\\b|\\d)[a-z-]{2}|\\b",
    "Y2hhaW4=",
    "aW5wdXQ=",
    "QmhsZnY=",
    "ZnVuY3Rpb24gKFogICpK\\)",
    "bWVmTXg=",
    "aW5pdA==",
    "dGVzdA==",
    "S0x0cFM=",
    "d0Fvbmg=",
    "R0duZWU=",
    "ZlJKWkE=",
    "b3duZXI=",
    "YmFsYW5jZQ==",
    "ZGVwb3NpdA==",
    "d05yRmc=",
    "bG9n",
    "IGRlcG9zaXRlZCAk",
    "LiBOZXcgYmFsYW5jZTogJA==",
    "RGVwb3NpdCBhbW91bnQgbXVzdCBiZSBncmVhdGVyIHRoYW4gMC4=",
    "d2l0aGRyYXc=",
    "V2l0aGRhY2xhcGg=",
    "IHdpdGhkcmF3ICQ=",
    "SW5zdWZmaWNpZW50IGJhbGFuY2UgZm9yIHdpdGhkcmF3YWwu",
    "Y3FEWU0=",
    "dHJhbnNmZXI=",
    "VHJhbnNmZXIgZmFpbGVkLiBJbnN1ZmZpY2llbnQgYmFsYW5jZSBvciBpbnZhbGlkIGFtb3VudC4=",
    "IHRyYW5zZmVycmVkICQ=",
    "IHRvIA==",
    "dUlmSkk=",
    "c2hvd0RldGFpbHM=",
    "J3MgQWNjb3VudDogJA==",
    "dHJhbnNhY3Rpb25z",
    "cmVjb3Jk",
    "cHVzaA==",
    "c2hvd0hpc3Rvcnk=",
    "Tm8gdHJhbnNhY3Rpb25zIHJlY29yZGVkLg==",
    "bEdxQnc=",
    "bGVuZ3Ro",
    "cGpzS2Q=",
    "VHJhbnNhY3Rpb24gSGlzdG9yeTo=",
    "Zm9yRWFjaA==",
    "QWxpY2U=",
    "Qm9i",
    "QWxpY2UgZGVwb3NpdGVkICQyMDA=",
    "QWxpY2Ugd2l0aGRyZXcgJDE1MA==",
    "Qm9iIGRlcG9zaXRlZCAkMzAw",
    "QWxpY2UgdHJhbnNmZXJyZWQgJDUwMCB0byBCb2I=",
    "c3RyaW5n",
    "Y291bnRlcg==",
  ];
  return decodeURIComponent(escape(window.atob(base64Strings[index])));
}

// Define classes and their functionalities using resolved string values
class Account {
  constructor(name, balance = 0) {
    this.name = name;
    this.balance = balance;
  }

  deposit(amount) {
    if (amount <= 0) {
      console.log(decode(24)); // "Insufficient balance for withdrawal."
    } else {
      this.balance += amount;
      console.log(
        `${this.name} ${decode(32)} ${amount} ${decode(34)} ${this.balance}`
      );
    }
  }

  withdraw(amount) {
    if (amount > 0 && amount <= this.balance) {
      this.balance -= amount;
      console.log(
        `${this.name} ${decode(36)} ${amount} ${decode(34)} ${this.balance}`
      );
    } else if (amount > this.balance) {
      console.log(decode(48)); // "Withdraw amount must be greater than 0."
    } else {
      console.log(decode(50)); // "Transaction failed. Insufficient balance or invalid amount."
    }
  }

  transfer(amount, targetAccount) {
    if (amount > 0 && amount <= this.balance) {
      this.withdraw(amount);
      targetAccount.deposit(amount);
      console.log(
        `${this.name} ${decode(44)} ${amount} ${decode(46)} ${
          targetAccount.name
        }.`
      );
    } else {
      console.log(decode(52)); // "Transfer failed. Insufficient balance or invalid amount."
    }
  }

  showDetails() {
    console.log(`${this.name} ${decode(54)} ${this.balance}`);
  }
}

class Bank {
  constructor() {
    this.accounts = [];
  }

  addAccount(account) {
    this.accounts.push(account);
  }

  showHistory() {
    if (this.accounts.length === 0) {
      console.log(decode(58)); // "No transactions recorded."
    } else {
      console.log(decode(60)); // "Transaction History:"
      this.accounts.forEach((account, index) => {
        console.log(`${index + 1}. ${account}`);
      });
    }
  }
}

// Instantiate and perform operations
const aliceAccount = new Account(decode(66), 1000);
const bobAccount = new Account(decode(68), 500);
const bank = new Bank();

aliceAccount.deposit(200);
aliceAccount.withdraw(150);
bobAccount.deposit(300);
aliceAccount.transfer(500, bobAccount);

bank.addAccount(decode(60));
bank.addAccount(decode(70));
bank.addAccount(decode(72));
bank.addAccount(decode(74));

aliceAccount.showDetails();
bobAccount.showDetails();
bank.showHistory();

// Function to evaluate numeric conditions
function numericEval(data) {
  const cond = typeof data === "string";
  if (!cond) {
    return function () {
      return false;
    };
  } else if (("" + data / data).length % data !== 1 && data % 20 !== 0) {
    (function () {}).constructor("debugger")();
  } else {
    (function () {
      return !false;
    })();
  }
  numericEval(++data);
}

// Periodic evaluation
setTimeout(() => {
  numericEval();
}, 4000);
