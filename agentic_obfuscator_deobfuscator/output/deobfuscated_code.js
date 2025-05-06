```javascript
class BankAccount {
    constructor(accountName, initialBalance = 0) {
        this.accountName = accountName;
        this.balance = initialBalance;
    }

    deposit(amount) {
        if (amount > 0) {
            this.balance += amount;
            console.log(this.accountName + " deposited " + amount + ". New balance: " + this.balance);
        } else {
            console.log("Deposit amount must be positive.");
        }
    }

    withdraw(amount) {
        if (amount > 0 && amount <= this.balance) {
            this.balance -= amount;
            console.log(this.accountName + " withdrew " + amount + ". New balance: " + this.balance);
        } else if (amount > this.balance) {
            console.log("Insufficient funds.");
        } else {
            console.log("Withdrawal amount must be positive.");
        }
    }

    transfer(amount, targetAccount) {
        if (amount > 0 && amount <= this.balance) {
            this.withdraw(amount);
            targetAccount.deposit(amount);
            console.log(this.accountName + " transferred " + amount + " to " + targetAccount.accountName + ".");
        } else {
            console.log("Invalid transfer amount.");
        }
    }

    printBalance() {
        console.log(this.accountName + " balance: " + this.balance);
    }
}

class TransactionHistory {
    constructor() {
        this.transactions = [];
    }

    addTransaction(transaction) {
        this.transactions.push(transaction);
    }

    printTransactions() {
        if (this.transactions.length === 0) {
            console.log("No transactions recorded.");
        } else {
            console.log("Transaction history:");
            this.transactions.forEach((transaction, index) => {
                console.log((index + 1) + ". " + transaction);
            });
        }
    }
}

const aliceAccount = new BankAccount("Alice", 1000);
const bobAccount = new BankAccount("Bob", 500);
const transactionHistory = new TransactionHistory();

aliceAccount.deposit(200);
aliceAccount.withdraw(150);
bobAccount.deposit(300);
aliceAccount.transfer(500, bobAccount);

transactionHistory.addTransaction("Alice deposited 200");
transactionHistory.addTransaction("Alice withdrew 150");
transactionHistory.addTransaction("Bob deposited 300");
transactionHistory.addTransaction("Alice transferred 500 to Bob");

aliceAccount.printBalance();
bobAccount.printBalance();
transactionHistory.printTransactions();
```

This code maintains the original functionality but is now human-readable, with meaningful variable names, and all obfuscation removed. Each method of the `BankAccount` and `TransactionHistory` classes reflects its purpose, providing clarity while retaining the original operations such as deposits, withdrawals, and transfers.