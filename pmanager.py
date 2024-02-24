import os
import json
import string
import secrets
from cryptography.fernet import Fernet, InvalidToken

class PasswordManager:
    def __init__(self, master_password):
        self.master_password = master_password
        self.key_file = "key.key"  # File to store the encryption key
        self.data_file = "passwords.enc"  # File to store encrypted data
        self.data = {}
        self.load_or_generate_key()

    def load_or_generate_key(self):
        if os.path.exists(self.key_file):
            self.load_key()
            if os.path.exists(self.data_file):
                self.decrypt_data()
        else:
            self.generate_key()

    def generate_key(self):
        self.key = Fernet.generate_key()
        with open(self.key_file, "wb") as key_file:
            key_file.write(self.key)

    def load_key(self):
        with open(self.key_file, "rb") as key_file:
            self.key = key_file.read()

    def encrypt_data(self):
        cipher_suite = Fernet(self.key)
        encrypted_data = cipher_suite.encrypt(json.dumps(self.data).encode())
        with open(self.data_file, "wb") as f:
            f.write(encrypted_data)

    def decrypt_data(self):
        cipher_suite = Fernet(self.key)
        try:
            with open(self.data_file, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
            self.data = json.loads(decrypted_data)
        except (FileNotFoundError, InvalidToken, json.decoder.JSONDecodeError) as e:
            print(f"Error: {e}")
            print("No existing data or data is corrupted.")

    def add_password(self, service, username, password):
        self.data[service] = {"username": username, "password": password}

    def get_password(self, service):
        return self.data.get(service, None)

    def delete_password(self, service):
        if service in self.data:
            del self.data[service]
            return True
        else:
            return False

    def save_data(self):
        self.encrypt_data()

    def load_data(self):
        self.decrypt_data()

    def generate_password(self, length=12):
        """Generate a random password."""
        characters = string.ascii_letters + string.digits + string.punctuation
        secure_random = secrets.SystemRandom()
        password = ''.join(secure_random.choice(characters) for _ in range(length))
        return password


def setup_master_password():
    try:
        master_password = input("\033[95mSet up your master password: \033[0m")
        return master_password
    except KeyboardInterrupt:
        print("\nExiting...")
        exit()

def main():
    print("Welcome to Password Manager! You can press CTRL+C anytime to quit.")

    # Check if the key file exists
    if not os.path.exists("key.key"):
        master_password = setup_master_password()
    else:
        try:
            master_password = input("\033[95Master Password: \033[0m")
        except KeyboardInterrupt:
            print("\nExiting...")
            exit()

    manager = PasswordManager(master_password)

    try:
        while True:
            print("\n1. Add a new service")
            print("2. Retrieve a service")
            print("3. Generate Password")
            print("4. Delete a service")
            choice = input("\033[92mChoose an option: \033[0m")

            if choice == "1":
                service = input("\033[95mEnter service name: \033[0m")
                username = input("\033[95mEnter username: \033[0m")
                password = input("\033[95mEnter password: \033[0m")
                manager.add_password(service, username, password)
                manager.save_data()
                print("\033[92mPassword added successfully!\033[0m")
            elif choice == "2":
                service = input("\033[95mEnter service name: \033[0m")
                data = manager.get_password(service)
                if data:
                    print("Username:", data["username"])
                    print("Password:", data["password"])
                else:
                    print("\033[91mPassword not found!\033[0m")
            elif choice == "3":
                length = int(input("\033[95mEnter password length: \033[0m"))
                service = input("\033[95mEnter service name to save this password: \033[0m")
                username = input("\033[95mEnter username: \033[0m")
                generated_password = manager.generate_password(length)
                print("\nGenerated Password:", generated_password)
                manager.add_password(service, username, generated_password)
                manager.save_data()
                print("\033[92mPassword added successfully!\033[0m")
            elif choice == "4":
                service = input("\033[95mEnter service name to delete its password: \033[0m")
                if manager.delete_password(service):
                    manager.save_data()
                    print("\033[92mPassword deleted successfully!\033[0m")
                else:
                    print("\033[91mService not found.\033[0m")
            else:
                print("\033[91mInvalid choice. Please try again.\033[0m")
    except KeyboardInterrupt:
        print("\nExiting...")

if __name__ == "__main__":
    main()