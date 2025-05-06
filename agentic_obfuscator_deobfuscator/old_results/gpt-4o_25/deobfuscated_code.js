// Deobfuscated code
function createLogger(name, initialBalance = 0) {
  return {
    name: name,
    balance: initialBalance,
    add(amount) {
      if (amount > 0) {
        this.balance += amount;
        console.log(`${this.name} has added: ${amount}. New balance: ${this.balance}`);
      } else {
        console.log(`Invalid amount!`);
      }
    },
    subtract(amount) {
      if (amount > 0 && amount <= this.balance) {
        this.balance -= amount;
        console.log(`${this.name} has subtracted: ${amount}. New balance: ${this.balance}`);
      } else if (amount > this.balance) {
        console.log("Subtraction amount exceeds current balance");
      } else {
        console.log(`Invalid amount!`);
      }
    },
    transfer(amount, toLogger) {
      if (amount > 0 && amount <= this.balance) {
        this.subtract(amount);
        toLogger.add(amount);
        console.log(`Transferred: ${amount} from ${this.name} to ${toLogger.name}.`);
      } else {
        console.log(`Transfer failed. Exceeds balance or invalid amount.`);
      }
    },
    showBalance() {
      console.log(`${this.name}'s balance: ${this.balance}`);
    },
  };
}

function manageTransactions(callback) {
  return function (...args) {
    return callback.apply(this, args);
  };
}

class AccountManager {
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
      console.log("Listing all accounts:");
      this.accounts.forEach((account, index) => {
        console.log(`${index + 1}. ${account.name}`);
      });
    }
  }
}

const mainAccount = createLogger("Main", 1000);
const secondaryAccount = createLogger("Secondary", 500);
const accountManager = new AccountManager();

mainAccount.add(200);                // Add 200 to the main account
mainAccount.subtract(150);           // Subtract 150 from the main account
secondaryAccount.add(300);           // Add 300 to the secondary account
mainAccount.transfer(500, secondaryAccount);  // Transfer 500 from main to secondary

accountManager.addAccount("beta");
accountManager.addAccount("gamma");
accountManager.addAccount("delta");
accountManager.addAccount("epsilon");

mainAccount.showBalance();           // Show balance of main account
secondaryAccount.showBalance();      // Show balance of secondary account
accountManager.listAccounts();       // List all accounts
