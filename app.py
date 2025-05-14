# app.py
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from web3 import Web3
import sqlite3
import time
from datetime import datetime
from io import BytesIO
import qrcode
from flask import send_file
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import os

app = Flask(__name__)

app.secret_key = 'crypto'  # Replace with a strong secret key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wallet.db'

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    eth_address = db.Column(db.String(42), nullable=True)  # User's Ethereum address
    encrypted_eth_private_key = db.Column(db.String(256), nullable=True)  # Store encrypted key
    salt = db.Column(db.String(32), nullable=True)  # Store unique salt for each user

# Initialize the database
with app.app_context():
    db.create_all()

# Initialize Web3 instance
INFURA_URL = "https://sepolia.infura.io/v3/73d61387f3db4ba6b97d050ba838337b"
w3 = Web3(Web3.HTTPProvider(INFURA_URL, request_kwargs={
    'timeout': 30,
    'headers': {"Content-Type": "application/json"}
}))

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please set up your wallet.', 'success')
            login_user(new_user)  # Auto-login after registration
            return redirect(url_for('setup_wallet'))
        except:
            db.session.rollback()
            flash('Username already exists. Try a different one.', 'danger')
    return render_template('register.html')

@app.route('/setup_wallet', methods=['GET', 'POST'])
@login_required
def setup_wallet():
    if current_user.eth_address:
        flash('You already have a wallet set up.', 'info')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        eth_address = request.form['eth_address']
        eth_private_key = request.form['eth_private_key']
        password = request.form['password']  # User's password for encryption
        
        # Validate Ethereum address
        if not w3.is_address(eth_address):
            flash('Invalid Ethereum address.', 'danger')
            return render_template('setup_wallet.html')
        
        # Validate private key (basic check)
        if not eth_private_key.startswith('0x') or len(eth_private_key) != 66:
            flash('Invalid private key format.', 'danger')
            return render_template('setup_wallet.html')
        
        # Generate a unique salt for the user
        salt = os.urandom(16)
        
        # Derive an encryption key from the password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        cipher = Fernet(key)
        
        # Encrypt the private key
        encrypted_key = cipher.encrypt(eth_private_key.encode())
        
        # Store the encrypted key and salt in the database
        current_user.eth_address = eth_address
        current_user.encrypted_eth_private_key = encrypted_key.decode()
        current_user.salt = salt.hex()  # Store salt as hex string
        db.session.commit()
        flash('Wallet set up successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('setup_wallet.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

def check_wallet_balance(address):
    balance_wei = w3.eth.get_balance(address)
    balance_eth = w3.from_wei(balance_wei, 'ether')
    return balance_wei, balance_eth

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/wallet')
@login_required
def wallet():
    if not current_user.eth_address:
        flash('Please set up your wallet first.', 'warning')
        return redirect(url_for('setup_wallet'))
    
    balance_wei = w3.eth.get_balance(current_user.eth_address)
    balance_eth = w3.from_wei(balance_wei, 'ether')
    wallet_info = {
        'eth_address': current_user.eth_address,
        'balance': balance_eth,
        # Private key is not displayed for security
    }
    return render_template('wallet.html', wallet=wallet_info)

@app.route('/balance', methods=['GET'])
@login_required
def get_balance():
    try:
        if not current_user.eth_address:
            return jsonify({"error": "No wallet set up."}), 400
        balance_wei = w3.eth.get_balance(current_user.eth_address)
        balance_eth = w3.from_wei(balance_wei, 'ether')
        return jsonify({"wallet_address": current_user.eth_address, "balance_eth": str(balance_eth)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/send_transaction', methods=['GET', 'POST'])
@login_required
def send_transaction():
    if not current_user.eth_address or not current_user.encrypted_eth_private_key:
        flash('Please set up your wallet first.', 'warning')
        return redirect(url_for('setup_wallet'))
    
    if request.method == 'POST':
        try:
            password = request.form['password']  # User's password to decrypt the private key
            recipient = request.form['recipient']
            amount = float(request.form['amount'])
            amount_wei = w3.to_wei(amount, 'ether')
            
            # Retrieve the user's salt and encrypted key
            salt = bytes.fromhex(current_user.salt)
            encrypted_key = current_user.encrypted_eth_private_key.encode()
            
            # Derive the encryption key from the password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            cipher = Fernet(key)
            
            # Decrypt the private key
            try:
                decrypted_key = cipher.decrypt(encrypted_key).decode()
            except Exception:
                flash('Invalid password', 'danger')
                return redirect(url_for('send_transaction'))
            
            balance_wei, balance_eth = check_wallet_balance(current_user.eth_address)
            if balance_wei == 0:
                raise ValueError("Your wallet has 0 ETH. Please fund it with Sepolia testnet ETH first.")
            
            if not w3.is_connected():
                raise Exception("Not connected to Ethereum network")
            if not w3.is_address(recipient):
                raise ValueError("Invalid recipient address")
            if not w3.is_address(current_user.eth_address):
                raise ValueError("Invalid sender address")
            
            gas_price = w3.eth.gas_price
            nonce = w3.eth.get_transaction_count(current_user.eth_address, 'pending')
            tx = {
                'nonce': nonce,
                'to': recipient,
                'value': amount_wei,
                'gas': 21000,
                'gasPrice': w3.to_wei('50', 'gwei'),
                'chainId': w3.eth.chain_id
            }
            total_cost_wei = (tx['gas'] * tx['gasPrice']) + amount_wei
            if balance_wei < total_cost_wei:
                raise ValueError(f"Insufficient funds! Need {w3.from_wei(total_cost_wei, 'ether')} ETH.")
            signed_tx = w3.eth.account.sign_transaction(tx, decrypted_key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            conn = sqlite3.connect('wallet.db')
            c = conn.cursor()
            c.execute("INSERT INTO transactions VALUES (?, ?, ?, ?)", (tx_hash.hex(), recipient, amount, time.time()))
            conn.commit()
            conn.close()
            
            return render_template('transaction_result.html', tx_hash=tx_hash.hex(), status="success")
        except ValueError as ve:
            return render_template('transaction_result.html', error=str(ve), status="error")
        except Exception as e:
            return render_template('transaction_result.html', error=str(e), status="error")
    
    balance_wei, balance_eth = check_wallet_balance(current_user.eth_address)
    return render_template('send_transaction.html', balance=balance_eth)

@app.route('/transaction_history')
@login_required
def transaction_history():
    conn = sqlite3.connect('wallet.db')
    c = conn.cursor()
    c.execute("SELECT * FROM transactions ORDER BY timestamp DESC")
    transactions = c.fetchall()
    conn.close()
    return render_template('transaction_history.html', transactions=transactions)

@app.route('/receive')
@login_required
def receive():
    if not current_user.eth_address:
        flash('Please set up your wallet first.', 'warning')
        return redirect(url_for('setup_wallet'))
    return render_template('receive.html', wallet_address=current_user.eth_address)

@app.route('/generate_qr')
@login_required
def generate_qr():
    if not current_user.eth_address:
        flash('Please set up your wallet first.', 'warning')
        return redirect(url_for('setup_wallet'))
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(current_user.eth_address)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')

@app.template_filter('datetime')
def format_datetime(value):
    return datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')

def init_db():
    conn = sqlite3.connect('wallet.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (tx_hash TEXT, recipient TEXT, amount REAL, timestamp REAL)''')
    conn.commit()
    conn.close()

init_db()

if __name__ == '__main__':
    app.run(debug=True)