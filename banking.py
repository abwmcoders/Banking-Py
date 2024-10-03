import sqlite3
import getpass
import bcrypt
from datetime import datetime

# Database Setup
def setup_db():
    conn = sqlite3.connect('banking.db')
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            balance REAL DEFAULT 0
        )
    ''')

    # Create transactions table for storing transaction history
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            transaction_type TEXT NOT NULL,
            amount REAL NOT NULL,
            target_user TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Validate Password Function
def validate_password(password):
    if len(password) < 5:
        print("Password must be at least 5 characters long.")
        return False
    elif not password:
        print("Password cannot be empty.")
        return False
    return True

# Hash Password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

# Check Password
def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

# User Registration
def register():
    conn = sqlite3.connect('banking.db')
    cursor = conn.cursor()

    print("=== Register ===")
    username = input("Enter a username: ")

    while True:
        password = getpass.getpass("Enter a password: ")
        if validate_password(password):
            break

    # Check if user already exists
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user:
        print("Username already exists. Try again.")
    else:
        hashed_password = hash_password(password)
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        print("Registration successful!")
    
    conn.close()

# User Login
def login():
    conn = sqlite3.connect('banking.db')
    cursor = conn.cursor()

    print("=== Login ===")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user:
        stored_password = user[2]  # Retrieve hashed password from DB
        if check_password(stored_password.encode('utf-8'), password):
            print(f"Welcome {username}!")
            return user[0]  # Return user ID
        else:
            print("Invalid password.")
    else:
        print("Invalid username.")
    
    return None

# Change Password
def change_password(user_id):
    conn = sqlite3.connect('banking.db')
    cursor = conn.cursor()

    while True:
        new_password = getpass.getpass("Enter new password: ")
        if validate_password(new_password):
            break

    hashed_password = hash_password(new_password)
    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
    conn.commit()
    print("Password changed successfully!")
    
    conn.close()

# Deposit Money
def deposit(user_id):
    conn = sqlite3.connect('banking.db')
    cursor = conn.cursor()

    amount = float(input("Enter amount to deposit: "))
    cursor.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
    balance = cursor.fetchone()[0]

    new_balance = balance + amount
    cursor.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user_id))
    conn.commit()

    # Add deposit transaction
    cursor.execute("INSERT INTO transactions (user_id, transaction_type, amount) VALUES (?, ?, ?)", 
                   (user_id, 'Deposit', amount))
    conn.commit()

    print(f"Deposit successful! New balance: ${new_balance:.2f}")
    conn.close()

# Withdraw Money
def withdraw(user_id):
    conn = sqlite3.connect('banking.db')
    cursor = conn.cursor()

    amount = float(input("Enter amount to withdraw: "))
    cursor.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
    balance = cursor.fetchone()[0]

    if amount > balance:
        print("Insufficient funds!")
    else:
        new_balance = balance - amount
        cursor.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user_id))
        conn.commit()

        # Add withdrawal transaction
        cursor.execute("INSERT INTO transactions (user_id, transaction_type, amount) VALUES (?, ?, ?)", 
                       (user_id, 'Withdrawal', amount))
        conn.commit()

        print(f"Withdrawal successful! New balance: ${new_balance:.2f}")
    
    conn.close()

# Transfer Money
def transfer(user_id):
    conn = sqlite3.connect('banking.db')
    cursor = conn.cursor()

    target_user = input("Enter the username to transfer to: ")
    amount = float(input("Enter amount to transfer: "))

    cursor.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
    sender_balance = cursor.fetchone()[0]

    cursor.execute("SELECT * FROM users WHERE username = ?", (target_user,))
    recipient = cursor.fetchone()

    if recipient:
        recipient_id = recipient[0]
        recipient_balance = recipient[3]

        if amount > sender_balance:
            print("Insufficient funds!")
        else:
            # Update sender's balance
            new_sender_balance = sender_balance - amount
            cursor.execute("UPDATE users SET balance = ? WHERE id = ?", (new_sender_balance, user_id))

            # Update recipient's balance
            new_recipient_balance = recipient_balance + amount
            cursor.execute("UPDATE users SET balance = ? WHERE id = ?", (new_recipient_balance, recipient_id))

            conn.commit()

            # Add transfer transaction for both users
            cursor.execute("INSERT INTO transactions (user_id, transaction_type, amount, target_user) VALUES (?, ?, ?, ?)", 
                           (user_id, 'Transfer Sent', amount, target_user))
            cursor.execute("INSERT INTO transactions (user_id, transaction_type, amount, target_user) VALUES (?, ?, ?, ?)", 
                           (recipient_id, 'Transfer Received', amount, target_user))
            conn.commit()

            print(f"Transfer successful! New balance: ${new_sender_balance:.2f}")
    else:
        print("Recipient user not found.")
    
    conn.close()

# Check Balance
def check_balance(user_id):
    conn = sqlite3.connect('banking.db')
    cursor = conn.cursor()

    cursor.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
    balance = cursor.fetchone()[0]
    
    print(f"Your balance: ${balance:.2f}")
    conn.close()

# View Transaction History
def view_transaction_history(user_id):
    conn = sqlite3.connect('banking.db')
    cursor = conn.cursor()

    print("\n=== Transaction History ===")
    cursor.execute("SELECT transaction_type, amount, target_user, timestamp FROM transactions WHERE user_id = ? ORDER BY timestamp DESC", (user_id,))
    transactions = cursor.fetchall()

    if transactions:
        for transaction in transactions:
            transaction_type, amount, target_user, timestamp = transaction
            if target_user:
                print(f"{timestamp} - {transaction_type}: ${amount:.2f} with {target_user}")
            else:
                print(f"{timestamp} - {transaction_type}: ${amount:.2f}")
    else:
        print("No transaction history available.")
    
    conn.close()

# Command-line Interface
def banking_menu(user_id):
    while True:
        print("\n=== Banking Menu ===")
        print("1. Deposit")
        print("2. Withdraw")
        print("3. Transfer")
        print("4. Check Balance")
        print("5. Transaction History")
        print("6. Change Password")
        print("7. Logout")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            deposit(user_id)
        elif choice == "2":
            withdraw(user_id)
        elif choice == "3":
            transfer(user_id)
        elif choice == "4":
            check_balance(user_id)
        elif choice == "5":
            view_transaction_history(user_id)
        elif choice == "6":
            change_password(user_id)
        elif choice == "7":
            print("Logged out successfully.")
            break
        else:
            print("Invalid choice. Try again.")

# Main Function
def main():
    setup_db()
    
    while True:
        print("\n=== Welcome to Command-line Banking ===")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            register()
        elif choice == "2":
            user_id = login()
            if user_id:
                banking_menu(user_id)
        elif choice == "3":
            print("Thank you for using Command-line Banking. Goodbye!")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
