from flask import Flask, render_template, request, redirect, session, url_for
from flask_bcrypt import Bcrypt
import mysql.connector

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management
bcrypt = Bcrypt(app)

# MySQL Database Connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="9090",
    database="finance_tracker"
)

cursor = db.cursor()

# SQL Queries
def get_user_by_username(username):
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    return cursor.fetchone()

def get_user_id(username):
    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    return cursor.fetchone()

def insert_user(username, hashed_password):
    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
    db.commit()

def insert_transaction(transaction_type, amount, description, user_id):
    cursor.execute("INSERT INTO transactions (type, amount, description, user_id) VALUES (%s, %s, %s, %s)", 
                   (transaction_type, amount, description, user_id))
    db.commit()

def get_user_transactions(user_id):
    cursor.execute("SELECT * FROM transactions WHERE user_id = %s", (user_id,))
    return cursor.fetchall()

def get_income(user_id):
    cursor.execute("SELECT SUM(amount) FROM transactions WHERE type = 'Income' AND user_id = %s", (user_id,))
    return cursor.fetchone()[0] or 0

def get_expenses(user_id):
    cursor.execute("SELECT SUM(amount) FROM transactions WHERE type = 'Expense' AND user_id = %s", (user_id,))
    return cursor.fetchone()[0] or 0

# Home route (redirect to login if not authenticated)
@app.route('/')
def index():
    if 'username' not in session:  # Check if the user is not logged in
        return redirect(url_for('login'))  # Redirect to login page

    user = get_user_id(session['username'])
    user_id = user[0] if user else None

    # Fetch transaction data only for the logged-in user
    transactions = get_user_transactions(user_id)

    income = get_income(user_id)
    expenses = get_expenses(user_id)
    balance = income - expenses

    return render_template('index.html', transactions=transactions, income=income, expenses=expenses, balance=balance, username=session['username'])

# User login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user_by_username(username)

        if user and bcrypt.check_password_hash(user[2], password):
            session['username'] = username  # Store username in session
            return redirect(url_for('index'))  # Redirect to home page
        else:
            return "Login failed. Check your username and password."

    return render_template('login.html')

# User logout route
@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove username from session
    return redirect(url_for('login'))  # Redirect to login page

# Add transaction route (requires login)
@app.route('/add', methods=['POST'])
def add_transaction():
    if 'username' not in session:  # Check if user is not logged in
        return redirect(url_for('login'))  # Redirect to login page

    # Get user_id based on the logged-in username
    user = get_user_id(session['username'])
    user_id = user[0] if user else None

    # Add the transaction if user is logged in
    transaction_type = request.form['type']
    amount = request.form['amount']
    description = request.form['description']
    
    insert_transaction(transaction_type, amount, description, user_id)
    
    return redirect('/')

# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        insert_user(username, hashed_password)

        return redirect(url_for('login'))

    return render_template('register.html')

if __name__ == "__main__":
    app.run(debug=True)
