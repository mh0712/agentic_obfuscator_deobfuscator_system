// Step 1: Decoding Base64 Encoded Strings
const strings = [
    "apply", "function *\\( *\\)", "\\+\\+ *(?:[a-zA-Z_$][0-9a-zA-Z_$]*)", "init",
    "test", "chain", "input", "owner", "balance", "deposit", "log", " deposited $",
    ". New balance: $", "Deposit amount must be greater than 0.", "withdraw",
    " withdrew $", "Insufficient balance for withdrawal.", "Withdrawal amount must be greater than 0.",
    "transfer", " transferred $", " to ", "Transfer failed. Insufficient balance or invalid amount.",
    "showDetails", "'s Account: $", "transactions", "record",
    "push", "showHistory", "length", "No transactions recorded.", "Transaction History:",
    "forEach", "Alice", "Bob", "Alice deposited $200", "Alice withdrew $150",
    "Bob deposited $300", "Alice transferred $500 to Bob", "string", "constructor",
    "while (true) {}", "counter", "debu", "gger", "call", "action", "stateObject"
];

// Step 2: Recovering Variables
function decodeBase64(encodedString) {
    return decodeURIComponent(
        Array.prototype.map.call(atob(encodedString), function (c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join('')
    );
}

function decodeString(index) {
  return strings[index];
};

// Step 3: Removing Self-Defending Logic
class BankAccount {
    constructor(owner, balance = 0) {
        this.owner = owner;
        this.balance = balance;
    }
    
    deposit(amount) {
        if (amount > 0) {
            this.balance += amount;
            console.log(this.owner + decodeString(10) + amount + decodeString(11) + this.balance);
        } else {
            console.log(decodeString(12));
        }
    }

    withdraw(amount) {
        if (amount > 0 && amount <= this.balance) {
            this.balance -= amount;
            console.log(this.owner + decodeString(14) + amount + decodeString(11) + this.balance);
        } else if (amount > this.balance) {
            console.log(decodeString(16));
        } else {
            console.log(decodeString(17));
        }
    }

    transfer(amount, account) {
        if (amount > 0 && amount <= this.balance) {
            this.withdraw(amount);
            account.deposit(amount);
            console.log(this.owner + decodeString(19) + amount + decodeString(20) + account.owner + ".");
        } else {
            console.log(decodeString(21));
        }
    }

    showDetails() {
        console.log(this.owner + decodeString(23) + this.balance);
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
            console.log(decodeString(28));
        } else {
            console.log(decodeString(29));
            this.transactions.forEach((transaction, index) => {
                console.log(index + 1 + ". " + transaction);
            });
        }
    }
}

// Step 4: Removing Debugger Protection
// Original self-defending code structures and infinite loops removed

const aliceAccount = new BankAccount(decodeString(32), 1000);
const bobAccount = new BankAccount(decodeString(33), 500);
const transactionHistory = new TransactionHistory();

aliceAccount.deposit(200);
aliceAccount.withdraw(150);
bobAccount.deposit(300);

aliceAccount.transfer(500, bobAccount);

transactionHistory.record(decodeString(34));
transactionHistory.record(decodeString(35));

setInterval(function () {
    // Removed any self-defeating logic here
}, 4000);

transactionHistory.record(decodeString(38));
transactionHistory.record(decodeString(39));

aliceAccount.showDetails();
bobAccount.showDetails();
transactionHistory.showHistory();
