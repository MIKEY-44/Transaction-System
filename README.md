# 💸 Blockchain-Based Transaction Management System

This is a **Blockchain-Based Transaction System** that allows users to send, receive, and track digital transactions securely through a web interface. Built using Flask and Web3.py, it simulates core concepts of blockchain and smart contract interactions — ideal for learning and demonstration purposes.

> 🔧 **Note**: This is a simulated environment and does not interact with a real blockchain network.

---

## 🧠 Built with AI Assistance

This project was **entirely built using AI assistance from ChatGPT (OpenAI)** and **DeepSeek Developer**, with guidance and support for architecture, implementation, and debugging.

---

## 🔍 Features

- 🪙 Send and receive transactions
- 📜 Transaction history tracking
- 🔐 User authentication system
- 🏦 SQLite-based backend database
- 🧠 Built using Flask, Web3.py, SQLAlchemy, QRCode, and Bcrypt

---

## 🛠 Technologies Used

| Stack        | Libraries / Tools                                 |
|--------------|---------------------------------------------------|
| **Backend**  | Python, Flask, SQLite                             |
| **Blockchain** | Web3.py (simulated Ethereum interactions)       |
| **Frontend** | HTML, CSS (Jinja templates)                       |
| **Security** | bcrypt, Flask-Login                               |
| **Others**   | qrcode, datetime, cryptography                    |

---



*## 📂 Project Structure *


BCTM-main/
│
├── app.py # Main Flask application

├── generator.py # Auxiliary utilities

├── wallet.db # SQLite database

├── static/ # Static assets (e.g. logo)

├── templates/ # HTML templates (Jinja2)

├── instance/ # Flask instance folder

├── requirements.txt # Python dependencies

├── .gitignore




*|Create a virtual environment|*

python3 -m venv venv

source venv/bin/activate  



*|Install dependencies|*

pip install -r requirements.txt


*|Run the app|*

python app.py



*📦 Dependencies*

Install with:

pip install flask flask_sqlalchemy flask_bcrypt flask_login web3 qrcode cryptography





*🙏 Acknowledgements*

Built with the help of ChatGPT (OpenAI) and DeepSeek Developer for code generation, architecture guidance, and debugging.

Flask documentation: https://flask.palletsprojects.com/

Web3.py documentation: https://web3py.readthedocs.io/

MetaMask for wallet  https://metamask.io
