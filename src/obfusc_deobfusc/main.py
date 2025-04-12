from dotenv import load_dotenv
from crew import obfuscation_crew
import os

load_dotenv()

def main():
    print("🔐 Obfuscation/Deobfuscation Tool 🔐")

    # Prompt user for file path
    file_path = input("📄 Enter path to your code file (e.g., samples/hello.py): ").strip()
    while not os.path.isfile(file_path):
        file_path = input("❌ File not found. Try again: ").strip()

    # Prompt user for operation
    operation = input("⚙️ Choose operation [obfuscate / deobfuscate]: ").strip().lower()
    while operation not in ["obfuscate", "deobfuscate"]:
        operation = input("❌ Invalid operation. Choose [obfuscate / deobfuscate]: ").strip().lower()

    print("\n🚀 Starting Obfuscation-Deobfuscation Crew...\n")

    result = obfuscation_crew.kickoff(inputs={
        "input": file_path,
        "operation": operation
    })

    print("\n✅ Final Result:\n")
    print(result)

if __name__ == "__main__":
    main()
