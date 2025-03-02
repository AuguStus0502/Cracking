import bcrypt
import mysql.connector
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from typing import List, Optional

# ✅ MySQL Database Configuration (XAMPP)
DB_CONFIG = {
    "host": "localhost",
    "user": "root",  # Default user in XAMPP
    "password": "",   # Default password (empty in XAMPP)
    "database": "email_forensics"
}

class DatabaseManager:
    """Handles MySQL connection and queries"""
    def __init__(self):
        self.connection = None
        self.cursor = None

    def connect(self):
        try:
            # Connect to MySQL server
            self.connection = mysql.connector.connect(
                host=DB_CONFIG["host"],
                user=DB_CONFIG["user"],
                password=DB_CONFIG["password"]
            )
            self.cursor = self.connection.cursor()

            # Create the database and switch to it
            self.create_database_and_tables()
        except mysql.connector.Error as err:
            messagebox.showerror("Database Error", f"❌ Failed to connect to MySQL: {err}")

    def create_database_and_tables(self):
        """Create database and necessary tables if they do not exist"""
        try:
            # Create the database if it doesn't exist
            self.cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
            self.connection.commit()  # Ensure changes are committed

            # Switch to the created database
            self.connection.database = DB_CONFIG['database']

            # Create the users table if it doesn't exist
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL
                )
            """)

            # Create the emails table if it doesn't exist
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS emails (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    sender VARCHAR(255),
                    receiver VARCHAR(255),
                    subject VARCHAR(255),
                    date_received DATETIME
                )
            """)
        except mysql.connector.Error as err:
            messagebox.showerror("Database Error", f"❌ Failed to create database or tables: {err}")

    def authenticate_user(self, username, password):
        """Check if the user exists in the database"""
        query = "SELECT * FROM users WHERE username = %s"
        self.cursor.execute(query, (username,))
        user = self.cursor.fetchone()
        if user:
            print(f"User found: {user}")  # Debugging statement
            # Compare the entered password with the stored hashed password
            if bcrypt.checkpw(password.encode(), user[2].encode()):
                print("Password match!")  # Debugging statement
                return True
            else:
                print("Incorrect password.")  # Debugging statement
        else:
            print("User not found.")  # Debugging statement
        return False

    def register_user(self, username, password):
        """Register a new user with hashed password"""
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        try:
            # Ensure the username doesn't already exist
            self.cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            if self.cursor.fetchone():
                return False  # Username already exists

            query = "INSERT INTO users (username, password) VALUES (%s, %s)"
            self.cursor.execute(query, (username, hashed_password))
            self.connection.commit()
            print(f"User registered: {username}")  # Debugging statement
            return True
        except mysql.connector.Error as err:
            print(f"Error during registration: {err}")  # Debugging statement
            return False

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Login/Register")
        self.root.geometry("300x250")

        ttk.Label(root, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(root)
        self.username_entry.pack()

        ttk.Label(root, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(root, show="*")
        self.password_entry.pack()

        self.login_button = ttk.Button(root, text="Login", command=self.authenticate)
        self.login_button.pack(pady=5)

        self.register_button = ttk.Button(root, text="Register", command=self.register)
        self.register_button.pack(pady=5)

    def authenticate(self):
        db = DatabaseManager()
        db.connect()
        if db.authenticate_user(self.username_entry.get(), self.password_entry.get()):
            self.root.destroy()
            main_root = tk.Tk()
            EmailForensicGUI(main_root)
            main_root.mainloop()
        else:
            messagebox.showerror("Login Failed", "Invalid Username or Password")

    def register(self):
        db = DatabaseManager()
        db.connect()
        if db.register_user(self.username_entry.get(), self.password_entry.get()):
            messagebox.showinfo("Success", "Registration Successful! Please Login.")
        else:
            messagebox.showerror("Error", "Username already exists or there was a problem registering.")

class BasicEmailParser:
    def __init__(self, file_path: str):
        self.file_path = file_path.strip('"')
        self.msg = None
        self.result_text = ""

        # ✅ Ensure Database Connection
        self.db_manager = DatabaseManager()
        self.db_manager.connect()

    def parse_email(self):
        try:
            with open(self.file_path, 'rb') as file:
                self.msg = BytesParser(policy=policy.default).parse(file)
            self._print_headers()
            self._trace_route()
            self._analyze_body()
            self._check_spf_dkim_dmarc()
            self._analyze_attachments()
            self.save_to_database()
        except (FileNotFoundError, OSError) as e:
            self.result_text += f"Error reading file: {e}\n"

    def _print_headers(self):
        headers = ["From", "To", "Subject", "Date", "Message-ID"]
        self.result_text += "\n=== EMAIL HEADER ANALYSIS ===\n"
        for header in headers:
            self.result_text += f"{header}: {self.msg.get(header, 'N/A')}\n"

    def _trace_route(self):
        received_headers = self.msg.get_all('Received', [])
        self.result_text += "\n--- Received Headers (Route Trace) ---\n"
        for i, header in enumerate(received_headers, 1):
            self.result_text += f"{i}. {header}\n"

    def _analyze_body(self):
        content = self._get_email_content(self.msg)
        if content:
            self._analyze_links(content)

    def _get_email_content(self, msg) -> str:
        content_parts = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ['text/plain', 'text/html']:
                    try:
                        content_parts.append(part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore'))
                    except (TypeError, UnicodeDecodeError):
                        continue
        else:
            try:
                return msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
            except (TypeError, UnicodeDecodeError):
                return ""
        return "\n".join(content_parts)

    def _analyze_links(self, content: str):
        soup = BeautifulSoup(content, 'html.parser')
        links = [link['href'] for link in soup.find_all('a', href=True)]
        self.result_text += "\n--- Extracted Links ---\n"
        for i, url in enumerate(links, 1):
            self.result_text += f"{i}. {url}\n"
        self.email_links = "\n".join(links) if links else "No links found"

    def _check_spf_dkim_dmarc(self):
        self.result_text += "\n--- Email Authentication Checks ---\n"
        self.result_text += f"SPF Check: {self.msg.get('Received-SPF', 'Not Available')}\n"
        self.result_text += f"DKIM Check: {self.msg.get('DKIM-Signature', 'Not Available')}\n"
        self.result_text += f"DMARC Check: {self.msg.get('Authentication-Results', 'Not Available')}\n"

    def save_to_database(self):
        sender = self.msg.get("From", "N/A")
        receiver = self.msg.get("To", "N/A")
        subject = self.msg.get("Subject", "N/A")
        date_received = self.msg.get("Date", "N/A")

        sql = """INSERT INTO emails (sender, receiver, subject, date_received) VALUES (%s, %s, %s, %s)"""
        values = (sender, receiver, subject, date_received)

        self.db_manager.cursor.execute(sql, values)
        self.db_manager.connection.commit()
        self.result_text += "\n✅ Email data saved to MySQL database.\n"

class EmailForensicGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Forensic Tool")
        self.root.geometry("800x550")
        self.file_path = None
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self.root, text="Email Forensic Tool", font=("Arial", 16, "bold")).pack(pady=10)
        self.file_button = ttk.Button(self.root, text="Browse", command=self.load_email_file)
        self.file_button.pack()
        self.analyze_button = ttk.Button(self.root, text="Analyze Email", command=self.analyze_email, state=tk.DISABLED)
        self.analyze_button.pack(pady=5)
        self.result_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=95, height=20)
        self.result_text.pack(pady=5, fill="both", expand=True)

    def load_email_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Email Files", "*.eml")])
        if self.file_path:
            self.analyze_button.config(state=tk.NORMAL)

    def analyze_email(self):
        parser = BasicEmailParser(self.file_path)
        parser.parse_email()
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, parser.result_text)

if __name__ == "__main__":
    root = tk.Tk()
    LoginWindow(root)
    root.mainloop()
