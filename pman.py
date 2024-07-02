import os
import json
import string
import secrets
import hashlib
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet, InvalidToken
import tkinter as tk
from tkinter import simpledialog, messagebox
from getpass import getpass
import sys
import platform

class PasswordManager:
    def __init__(self, master_password):
        self.master_password = master_password
        self.key_file = os.getenv("KEY_FILE", "key.key")
        self.data_file = os.getenv("DATA_FILE", "passwords.enc")
        self.data = {}
        self.key = self.derive_key_from_password(master_password)
        self.load_or_generate_key()

    def derive_key_from_password(self, password):
        salt = b'some_salt'  # Use a fixed salt or generate one and save it securely
        kdf = hashlib.pbkdf2_hmac(
            'sha256', password.encode(), salt, 100000, dklen=32
        )
        return urlsafe_b64encode(kdf)

    def load_or_generate_key(self):
        if os.path.exists(self.key_file):
            self.load_key()
            if os.path.exists(self.data_file):
                self.decrypt_data()
        else:
            self.generate_key()

    def generate_key(self):
        with open(self.key_file, "wb") as key_file:
            key_file.write(self.key)

    def load_key(self):
        with open(self.key_file, "rb") as key_file:
            stored_key = key_file.read()
        if stored_key != self.key:
            raise ValueError("Incorrect master password.")

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
            messagebox.showerror("Error", f"Failed to load data: {e}")
            print(f"Error: {e}")

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

    def list_services(self):
        return list(self.data.keys())

    def save_data(self):
        self.encrypt_data()

    def load_data(self):
        self.decrypt_data()

    def generate_password(self, length=12):
        characters = string.ascii_letters + string.digits + string.punctuation
        secure_random = secrets.SystemRandom()
        password = ''.join(secure_random.choice(characters) for _ in range(length))
        return password

def center_dialog(dialog):
    dialog.update_idletasks()
    width = dialog.winfo_width()
    height = dialog.winfo_height()
    screen_width = dialog.winfo_screenwidth()
    screen_height = dialog.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    dialog.geometry(f'{width}x{height}+{x}+{y}')

def setup_master_password():
    root = tk.Tk()
    root.withdraw()  # Hide the main window

    master_password = None
    while not master_password:
        password_dialog = simpledialog.askstring("Master Password Setup", "Set up your master password:", show='*', parent=root)
        center_dialog(root)
        if not password_dialog:
            if messagebox.askyesno("Exit", "Master password setup is required. Do you want to exit?", parent=root):
                root.destroy()
                sys.exit()
        confirm_password = simpledialog.askstring("Master Password Setup", "Confirm your master password:", show='*', parent=root)
        center_dialog(root)
        if password_dialog != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.", parent=root)
        else:
            master_password = password_dialog

    root.destroy()  # Destroy the temporary root window
    return master_password

def secure_input(prompt):
    root = tk.Tk()
    root.withdraw()  # Hide the main window

    password = simpledialog.askstring("Input", prompt, show='*', parent=root)
    center_dialog(root)

    root.destroy()  # Destroy the temporary root window
    return password

class PasswordManagerGUI:
    def __init__(self, root, master_password):
        self.root = root
        self.root.title("Password Manager")
        self.manager = None
        self.center_window(self.root, 300, 200)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        try:
            self.manager = PasswordManager(master_password)
        except ValueError as e:
            messagebox.showerror("Error", "Incorrect master password.", parent=self.root)
            self.root.destroy()
            return

        self.create_widgets()

    def create_widgets(self):
        tk.Button(self.root, text="Add Service", command=self.add_service).pack(fill='x')
        tk.Button(self.root, text="Retrieve Service", command=self.retrieve_service).pack(fill='x')
        tk.Button(self.root, text="Generate Password", command=self.generate_password).pack(fill='x')
        tk.Button(self.root, text="Delete Service", command=self.delete_service).pack(fill='x')
        tk.Button(self.root, text="List Services", command=self.list_services).pack(fill='x')

    def add_service(self):
        service = simpledialog.askstring("Add Service", "Enter service name:", parent=self.root)
        username = simpledialog.askstring("Add Service", "Enter username:", parent=self.root)
        password = simpledialog.askstring("Add Service", "Enter password:", show='*', parent=self.root)
        if service and username and password:
            try:
                self.manager.add_password(service, username, password)
                self.manager.save_data()
                messagebox.showinfo("Success", "Password added successfully!", parent=self.root)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add password: {e}", parent=self.root)
        else:
            messagebox.showerror("Error", "All fields are required.", parent=self.root)

    def retrieve_service(self):
        service = simpledialog.askstring("Retrieve Service", "Enter service name:", parent=self.root)
        if service:
            data = self.manager.get_password(service)
            if data:
                messagebox.showinfo("Service Details", f"Username: {data['username']}\nPassword: {data['password']}", parent=self.root)
            else:
                messagebox.showerror("Error", "Service not found.", parent=self.root)
        else:
            messagebox.showerror("Error", "Service name is required.", parent=self.root)

    def generate_password(self):
        length = simpledialog.askinteger("Generate Password", "Enter password length:", minvalue=1, parent=self.root)
        if length:
            service = simpledialog.askstring("Generate Password", "Enter service name to save this password:", parent=self.root)
            username = simpledialog.askstring("Generate Password", "Enter username:", parent=self.root)
            if service and username:
                try:
                    generated_password = self.manager.generate_password(length)
                    self.manager.add_password(service, username, generated_password)
                    self.manager.save_data()
                    messagebox.showinfo("Generated Password", f"Generated Password: {generated_password}\nPassword added successfully!", parent=self.root)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to generate password: {e}", parent=self.root)
            else:
                messagebox.showerror("Error", "All fields are required.", parent=self.root)
        else:
            messagebox.showerror("Error", "Password length is required.", parent=self.root)

    def delete_service(self):
        service = simpledialog.askstring("Delete Service", "Enter service name:", parent=self.root)
        if service:
            try:
                if self.manager.delete_password(service):
                    self.manager.save_data()
                    messagebox.showinfo("Success", "Password deleted successfully!", parent=self.root)
                else:
                    messagebox.showerror("Error", "Service not found.", parent=self.root)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete service: {e}", parent=self.root)
        else:
            messagebox.showerror("Error", "Service name is required.", parent=self.root)

    def list_services(self):
        try:
            services = self.manager.list_services()
            if services:
                services_list = "\n".join(services)
                messagebox.showinfo("Current Services", services_list, parent=self.root)
            else:
                messagebox.showinfo("No Services", "No services found.", parent=self.root)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list services: {e}", parent=self.root)

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?", parent=self.root):
            self.root.destroy()

    def center_window(self, window, width, height):
        window.update_idletasks()
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        window.geometry(f'{width}x{height}+{x}+{y}')

if __name__ == "__main__":
    try:
        if not os.path.exists(os.getenv("KEY_FILE", "key.key")):
            master_password = setup_master_password()
        else:
            master_password = secure_input("Master Password: ")

        root = tk.Tk()
        app = PasswordManagerGUI(root, master_password)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Fatal Error", f"An unexpected error occurred: {e}")
        sys.exit()
