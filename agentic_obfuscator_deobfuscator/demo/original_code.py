class BankAccount:
    def __init__(self, owner, balance=0):
        self.owner = owner
        self.balance = balance

    # Deposit money into the account
    def deposit(self, amount):
        if amount > 0:
            self.balance += amount
            print(f"{self.owner} deposited ${amount}. New balance: ${self.balance}")
        else:
            print("Deposit amount must be greater than 0.")

    # Withdraw money from the account
    def withdraw(self, amount):
        if amount > 0 and amount <= self.balance:
            self.balance -= amount
            print(f"{self.owner} withdrew ${amount}. New balance: ${self.balance}")
        elif amount > self.balance:
            print("Insufficient balance for withdrawal.")
        else:
            print("Withdrawal amount must be greater than 0.")

    # Transfer money to another bank account
    def transfer(self, amount, recipient):
        if amount > 0 and amount <= self.balance:
            self.withdraw(amount)
            recipient.deposit(amount)
            print(f"{self.owner} transferred ${amount} to {recipient.owner}.")
        else:
            print("Transfer failed. Insufficient balance or invalid amount.")

    # Display account details
    def show_details(self):
        print(f"{self.owner}'s Account: ${self.balance}")


class TransactionHistory:
    def __init__(self):
        self.transactions = []

    # Record a transaction
    def record(self, transaction):
        self.transactions.append(transaction)

    # Display all recorded transactions
    def show_history(self):
        if not self.transactions:
            print("No transactions recorded.")
        else:
            print("Transaction History:")
            for index, transaction in enumerate(self.transactions, start=1):
                print(f"{index}. {transaction}")


# Create instances of BankAccount
alice_account = BankAccount("Alice", 1000)
bob_account = BankAccount("Bob", 500)

# Create a TransactionHistory instance
transaction_history = TransactionHistory()

# Perform some operations
alice_account.deposit(200)
alice_account.withdraw(150)
bob_account.deposit(300)
alice_account.transfer(500, bob_account)

# Record transactions
transaction_history.record("Alice deposited $200")
transaction_history.record("Alice withdrew $150")
transaction_history.record("Bob deposited $300")
transaction_history.record("Alice transferred $500 to Bob")

# Display account details
alice_account.show_details()
bob_account.show_details()

# Display transaction history
transaction_history.show_history()
