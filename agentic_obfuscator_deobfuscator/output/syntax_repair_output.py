```python
class Account:
    def __init__(self, owner_name, balance=0):
        self.owner_name = owner_name
        self.balance = balance

    def deposit(self, amount):
        if amount > 0:
            self.balance += amount
            print(f"{self.owner_name} deposited ${amount}. New balance: ${self.balance}")
        else:
            print("Deposit amount must be greater than 0.")

    def withdraw(self, amount):
        if amount > 0 and amount <= self.balance:
            self.balance -= amount
            print(f"{self.owner_name} withdrew ${amount}. New balance: ${self.balance}")
        elif amount > self.balance:
            print("Insufficient balance for withdrawal.")
        else:
            print("Withdrawal amount must be greater than 0.")

    def transfer(self, amount, recipient):
        if amount > 0 and amount <= self.balance:
            self.withdraw(amount)
            recipient.deposit(amount)
            print(f"{self.owner_name} transferred ${amount} to {recipient.owner_name}.")
        else:
            print("Transfer failed. Insufficient balance or invalid amount.")

    def show_details(self):
        print(f"{self.owner_name}'s Account: ${self.balance}")


class TransactionHistory:
    def __init__(self):
        self.transactions = []

    def record(self, transaction):
        self.transactions.append(transaction)

    def show_history(self):
        if not self.transactions:
            print("No transactions recorded.")
        else:
            print("Transaction History:")
            for index, transaction in enumerate(self.transactions):
                print(f"{index + 1}. {transaction}")


alice_account = Account("Alice", 1000)
bob_account = Account("Bob", 500)
transaction_history = TransactionHistory()

alice_account.deposit(200)
alice_account.withdraw(150)
bob_account.deposit(300)
alice_account.transfer(500, bob_account)

for log in [
    "Alice deposited $200",
    "Alice withdrew $150",
    "Bob deposited $300",
    "Alice transferred $500 to Bob"
]:
    transaction_history.record(log)

alice_account.show_details()
bob_account.show_details()
transaction_history.show_history()
```

The provided code is now completely syntactically valid and executable. It depicts a simple banking system with accounts and a transaction history management, and includes all the functionalities correctly.