🔍 Foundational Overview

1. What is the overall goal of this project?
The goal is to simulate a blockchain-based transaction management system where users can register, generate wallet addresses, and send transactions in a secure and traceable manner. It demonstrates blockchain concepts like decentralization, digital wallets, and hashing.


2. How does this simulate or use blockchain technology?
This project simulates blockchain transactions using Flask and local storage (wallet.db). It mimics Ethereum wallet generation and transaction flows, without connecting to a real blockchain. Web3-related methods are simulated.




🗄️ Database

3. Where is the database located and how is it structured?
The database is wallet.db, stored locally using SQLite. It holds user data, wallet addresses, and transaction logs.


4. What ORM is used to interact with the database?
SQLAlchemy is used as the ORM to define and manage the database models (User, Transaction, etc.).


5. How is sensitive user data stored?
User passwords are securely hashed using the bcrypt algorithm before being stored in the database.



🔐 Authentication & Security


6. Which authentication method is used?
Flask-Login is used for session-based authentication, managing user login states securely with session cookies.


7. What encryption/hashing is used for passwords and why?
The bcrypt library is used for hashing passwords. Bcrypt is chosen because it is computationally expensive, making it resistant to brute-force attacks.


8. How are QR codes used?
QR codes are generated for Ethereum wallet addresses using the qrcode library, enabling quick sharing or scanning of public addresses.




💰 Blockchain & Web3

9. Why is MetaMask used?
MetaMask is used to simulate real-world Ethereum transactions and wallet integration. In an advanced setup, it would allow users to sign and send real transactions via their browser wallet.


10. Is Web3.py used for real Ethereum transactions?
Web3.py is integrated, but the current code does not appear to broadcast real Ethereum transactions — it mimics interactions to simulate blockchain behavior locally.


11. How are Ethereum addresses managed?
Addresses are randomly generated and stored in the database. No actual private key handling or Ethereum node interaction is present in this version.


12. Is there smart contract functionality?
No smart contracts are deployed or interacted with in the current implementation.




🔗 Hashing, Signing, and Security Logic


13. Where is hashing used and for what?
Hashing is primarily used for password protection (bcrypt). If transaction hashes are generated, they serve as unique identifiers to simulate blockchain behavior.


14. Are transactions signed before sending?
No cryptographic signing of transactions is currently implemented. This would be needed in a real blockchain scenario.


15. What measures prevent fraud/tampering?
Security is maintained via:
Hashed passwords
Session-based login
Input validation
However, no advanced blockchain fraud detection is implemented due to the simulated nature.



🧪 Functionality & Workflow

16. What is the user workflow?
Register
Log in
Generate wallet address
Send transaction (recipient address + amount)
View transaction history


18. How are transactions validated?
Transactions are locally validated (e.g., balance check, valid address), but not confirmed via blockchain miners or consensus.


19. Is this a hot, cold, or simulated wallet?
It’s a simulated wallet — no actual blockchain private keys or on-chain interactions are implemented.




🧱 Architecture & Design

19. Why Flask?
Flask offers simplicity and flexibility, making it ideal for small-scale blockchain simulations and fast prototyping.


20. Any design patterns used?
The project loosely follows the MVC pattern, where:
Models = SQLAlchemy classes
Views = HTML templates
Controllers = Flask route functions


21. How are errors handled?
Basic error handling is in place (e.g., login errors, input validation), but could be improved with centralized exception handling and Flask error pages.




📈 Future Scope & Enhancements

22. Is this architecture scalable?
Not in its current form. It's a single-server app using SQLite and lacks on-chain transaction support. For scalability:
Switch to PostgreSQL
Use Docker for deployment
Integrate with Ethereum testnet


23. Plans to integrate a real testnet like Goerli or Sepolia?
Yes — this would be a natural next step. You can connect Web3.py to an Infura or Alchemy endpoint and use real test ETH with MetaMask.


24. Enhancement ideas:
Deploy smart contracts (ERC-20 or custom)
Add wallet recovery or seed phrase export
Enable MetaMask transaction signing
Add 2FA for login


26. How would you deploy this securely?
Use Render, Vercel, or Heroku for deployment
Enable HTTPS with SSL
Store secrets using environment variables (.env)
Restrict database access
Use a production server like gunicorn
