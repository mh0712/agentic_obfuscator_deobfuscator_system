// Base64 Decoding function
function decodeBase64(encodedStr) {
    let str = atob(encodedStr);
    let decodedStr = '';
    for (let i = 0; i < str.length; i++) {
        decodedStr += '%' + ('00' + str.charCodeAt(i).toString(16)).slice(-2);
    }
    return decodeURIComponent(decodedStr);
}

const strings = [
    "YXBwbHk=",                // "apply"
    "ZnVuY3Rpb24gKlwoICpcKQ==",// "function *() *()"
    "XCtcKyAqKD86XzB4KD86W2EtZjAtOV0pezQsNn18KD86XGJ8XGQpW2EtejAtOV17MSw0fSg/OlxifFxkKSk=", // complex regex
    "aW5pdA==",                // "init"
    "dGVzdA==",                // "test"
    "Y2hhaW4=",                // "chain"
    "aW5wdXQ=",                // "input"
    "b3duZXI=",                // "owner"
    "YmFsYW5jZQ==",            // "balance"
    "ZGVwb3NpdA==",            // "deposit"
    "bG9n",                    // "log"
    "IGRlcG9zaXRlZCAk",        // " deposited $"
    "LiBOZXcgYmFsYW5jZTogJA==",// ". New balance: $"
    "RGVwb3NpdCBhbW91bnQgbXVzdCBiZSBncmVhdGVyIHRoYW4gMC4=", // "Deposit amount must be greater than 0."
    "d2l0aGRyYXc=",            // "withdraw"
    "IHdpdGhkcmV3ICQ=",        // " withdraw $"
    "SW5zdWZmaWNpZW50IGJhbGFuY2UgZm9yIHdpdGhkcmF3YWwu", // "Insufficient balance for withdrawal."
    "V2l0aGRyYXdhbCBhbW91bnQgbXVzdCBiZSBncmVhdGVyIHRoYW4gMC4=", // "Withdrawal amount must be greater than 0."
    "dHJhbnNmZXI=",            // "transfer"
    "IHRyYW5zZmVycmVkICQ=",    // " transferred $"
    "IHRvIA==",                // " to "
    "VHJhbnNmZXIgZmFpbGVkLiBJbnN1ZmZpY2llbnQgYmFsYW5jZSBvciBpbnZhbGlkIGFtb3VudC4=", // "Transfer failed. Insufficient balance or invalid amount."
    "c2hvd0RldGFpbHM=",        // "showDetails"
    "J3MgQWNjb3VudDogJA==",    // "'s Account: $"
    "dHJhbnNhY3Rpb25z",        // "transactions"
    "cmVjb3Jk",                // "record"
    "cHVzaA==",                // "push"
    "c2hvd0hpc3Rvcnk=",        // "showHistory"
    "bGVuZ3Ro",                // "length"
    "Tm8gdHJhbnNhY3Rpb25zIHJlY29yZGVkLg==", // "No transactions recorded."
    "VHJhbnNhY3Rpb24gSGlzdG9yeTo=", // "Transaction History:"
    "Zm9yRWFjaA==",            // "forEach"
    "QWxpY2U=",                // "Alice"
    "Qm9i",                    // "Bob"
    "QWxpY2UgZGVwb3NpdGVkICQyMDA=", // "Alice deposited $200"
    "QWxpY2Ugd2l0aGRyZXcgJDE1MA==", // "Alice withdrew $150"
    "Qm9iIGRlcG9zaXRlZCAkMzAw", // "Bob deposited $300"
    "QWxpY2UgdHJhbnNmZXJyZWQgJDUwMCB0byBCb2I=", // "Alice transferred $500 to Bob"
    "c3RyaW5n",                // "string"
    "Y29uc3RydWN0b3I=",        // "constructor"
    "d2hpbGUgKHRydWUpIHt9",    // "while (true) {}"
    "Y291bnRlcg==",            // "counter"
    "ZGVidQ==",                // "debug"
    "Z2dlcg==",                // "gger"
    "Y2FsbA==",                // "call"
    "YWN0aW9u",                // "action"
    "c3RhdGVPYmplY3Q=",        // "stateObject"
];

// New Functions Decoded from Base64
function _0x1c70(index) {
    // Decoding the string
    return decodeBase64(strings[index].slice(0, -4));
}

class BankAccount {
    constructor(ownerName, balance = 0) {
        this.owner = ownerName;
        this.balance = balance;
    }

    deposit(amount) {
        if (amount > 0) {
            this.balance += amount;
            console.log(this.owner + " deposited $" + amount + ". New balance: $" + this.balance);
        } else {
            console.log("Deposit amount must be greater than 0.");
        }
    }

    withdraw(amount) {
        if (amount > 0 && amount <= this.balance) {
            this.balance -= amount;
            console.log(this.owner + " withdraw $" + amount + ". New balance: $" + this.balance);
        } else if (amount > this.balance) {
            console.log("Insufficient balance for withdrawal.");
        } else {
            console.log("Withdrawal amount must be greater than 0.");
        }
    }

    transfer(amount, toAccount) {
        if (amount > 0 && amount <= this.balance) {
            this.withdraw(amount);
            toAccount.deposit(amount);
            console.log(this.owner + " transferred $" + amount + " to " + toAccount.owner + ".");
        } else {
            console.log("Transfer failed. Insufficient balance or invalid amount.");
        }
    }

    showDetails() {
        console.log(this.owner + "'s Account: $" + this.balance);
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

// Initialize accounts
const aliceAccount = new BankAccount("Alice", 1000);
const bobAccount = new BankAccount("Bob", 500);
const transactionHistory = new TransactionHistory();

// Execute transactions
aliceAccount.deposit(200);
aliceAccount.withdraw(150);
bobAccount.deposit(300);
aliceAccount.transfer(500, bobAccount);

// Record transactions
transactionHistory.record("Alice deposited $200");
transactionHistory.record("Alice withdrew $150");

// Timed function removed for simplification (e.g. setInterval)
transactionHistory.record("Bob deposited $300");
transactionHistory.record("Alice transferred $500 to Bob");

// Display account details and transaction history
aliceAccount.showDetails();
bobAccount.showDetails();
transactionHistory.showHistory();
