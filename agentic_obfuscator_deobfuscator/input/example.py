# This is a simple Python script to test the obfuscation and deobfuscation system

def greet(name):
    """
    Function to greet the user.
    """
    print(f"Hello, {name}!")

def add(a, b):
    """
    Function to add two numbers.
    """
    return a + b

def complex_function(x):
    """
    Function to simulate a complex operation.
    """
    result = 0
    for i in range(1000):
        result += (x * i) / (i + 1)
    return result

# Main execution
if __name__ == "__main__":
    name = "John"
    greet(name)
    sum_result = add(5, 10)
    print(f"The sum of 5 and 10 is: {sum_result}")
    complex_result = complex_function(42)
    print(f"Complex function result: {complex_result}")
