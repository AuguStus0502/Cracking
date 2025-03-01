import mysql.connector
from mysql.connector import errorcode
import itertools
import time
import hashlib
import tkinter as tk
from tkinter import messagebox
from tkinter.ttk import Progressbar
import threading

# Establish a connection to MySQL without specifying a database
def create_database():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            passwd=""  # Default XAMPP has no password
        )
        cursor = conn.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS hash_cracker DEFAULT CHARACTER SET 'utf8'")
        print("Database created or already exists.")
    except mysql.connector.Error as err:
        print(f"Failed creating database: {err}")
        exit(1)
    finally:
        cursor.close()
        conn.close()

# Connect to the specific database
def connect_database():
    try:
        db = mysql.connector.connect(
            host="localhost",
            user="root",
            passwd="",
            database="hash_cracker"
        )
        return db
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_BAD_DB_ERROR:
            create_database()
            db = connect_database()  # Try connecting again after creating the database
        else:
            print(err)
            exit(1)
    return db

def create_table(db):
    table_query = """
    CREATE TABLE IF NOT EXISTS results (
        id INT AUTO_INCREMENT PRIMARY KEY,
        hash VARCHAR(255) NOT NULL,
        cracked_password VARCHAR(255),
        attempts INT,
        time_taken FLOAT
    );
    """
    cursor = db.cursor()
    try:
        cursor.execute(table_query)
        print("Table created or already exists.")
    except mysql.connector.Error as err:
        print(f"Failed creating table: {err}")
    finally:
        cursor.close()

# Load rockyou.txt for dictionary-based attack
def load_wordlist(filename="rockyou.txt"):
    try:
        with open(filename, "r", encoding="latin-1") as f:
            return [line.strip() for line in f]
    except FileNotFoundError:
        return None

# Function to hash a guessed password and compare it
def hash_md5(text):
    return hashlib.md5(text.encode()).hexdigest()

# Brute-force MD5 hash cracker function
def brute_force_crack(md5_hash):
    chars = 'abcdefghijklmnopqrstuvwxyz'
    attempts = 0
    start_time = time.time()
    wordlist = load_wordlist()
    if wordlist:
        for word in wordlist:
            attempts += 1
            update_display(word, attempts)
            if hash_md5(word) == md5_hash:
                time_taken = time.time() - start_time
                insert_result(md5_hash, word, attempts, time_taken)
                return word, attempts, time_taken

    for length in range(1, 6):
        for guess in itertools.product(chars, repeat=length):
            attempts += 1
            guessed_password = ''.join(guess)
            update_display(guessed_password, attempts)
            if hash_md5(guessed_password) == md5_hash:
                time_taken = time.time() - start_time
                insert_result(md5_hash, guessed_password, attempts, time_taken)
                return guessed_password, attempts, time_taken

    insert_result(md5_hash, None, attempts, 0)  # Insert failed attempt
    return None, attempts, 0

# Update UI display with password guess and attempts
def update_display(guessed_pass, attempts):
    text_display.config(state=tk.NORMAL)
    text_display.insert(tk.END, f"{guessed_pass}\n")
    text_display.config(state=tk.DISABLED)
    text_display.see(tk.END)
    progress_bar['value'] = min((attempts % 100), 100)
    root.update_idletasks()

# Start cracking process
def start_cracking():
    md5_hash = password_entry.get()
    if len(md5_hash) == 32 and all(c in "0123456789abcdefABCDEF" for c in md5_hash):
        text_display.config(state=tk.NORMAL)
        text_display.delete(1.0, tk.END)
        text_display.config(state=tk.DISABLED)
        progress_bar['value'] = 0
        crack_thread = threading.Thread(target=crack_password_threaded, args=(md5_hash,))
        crack_thread.start()
    else:
        messagebox.showwarning("Input Error", "Please enter a valid 32-character MD5 hash.")

# Function to run cracking logic in a thread
def crack_password_threaded(md5_hash):
    cracked_password, attempts, time_taken = brute_force_crack(md5_hash)
    if cracked_password:
        messagebox.showinfo("Success", f"Password Cracked: {cracked_password}\nAttempts: {attempts}\nTime: {time_taken:.2f} seconds")
    else:
        messagebox.showerror("Failed", "Password could not be cracked. Use a stronger password!")

# Function to insert results into the database
def insert_result(hash_value, cracked_password, attempts, time_taken):
    db = connect_database()  # Ensure a fresh connection for thread safety
    local_cursor = db.cursor()
    try:
        query = "INSERT INTO results (hash, cracked_password, attempts, time_taken) VALUES (%s, %s, %s, %s)"
        values = (hash_value, cracked_password, attempts, time_taken)
        local_cursor.execute(query, values)
        db.commit()
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
    finally:
        local_cursor.close()  # Make sure to close the cursor
        db.close()  # and the connection

# Set up UI
root = tk.Tk()
root.title("MD5 Hash Cracker")
root.configure(bg='#1e1e1e')

frame = tk.Frame(root, bg='#1e1e1e')
frame.pack(padx=10, pady=10)

# MD5 Hash input
password_label = tk.Label(frame, text="Enter MD5 Hash:", fg='#ffffff', bg='#1e1e1e')
password_label.pack(pady=5)

password_entry = tk.Entry(frame, width=35, bg='#333333', fg='#ffffff', insertbackground='white')
password_entry.pack(pady=5)

# Start button
start_button = tk.Button(frame, text="Start Cracking", command=start_cracking, bg='#444444', fg='#ffffff', activebackground='#555555')
start_button.pack(pady=10)

# Progress bar
progress_bar = Progressbar(frame, orient='horizontal', length=300, mode='determinate')
progress_bar.pack(pady=10)

# Text display
text_display = tk.Text(frame, height=15, width=60, state=tk.DISABLED, bg='#1e1e1e', fg='#00ff00', insertbackground='white')
text_display.pack(padx=5, pady=5)

# Scrollbar for text display
scrollbar = tk.Scrollbar(frame, command=text_display.yview, bg='#1e1e1e')
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
text_display['yscrollcommand'] = scrollbar.set

root.mainloop()
