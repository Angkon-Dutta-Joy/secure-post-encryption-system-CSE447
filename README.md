secure-post-encryption-system-CSE447
CSE447 Secure Database Project

A security-focused application demonstrating user authentication, database encryption, post encryption, key management, and data integrity using cryptographic techniques.

Features
User registration and login
SHA-256 password hashing with random salt
AES-256-CBC database field encryption
RSA-2048 post encryption
HMAC-SHA256 integrity verification
Encrypted RSA private keys
MongoDB database
Technologies
Python 3.7+
MongoDB
RSA-2048
AES-256-CBC
SHA-256
HMAC-SHA256
Setup
Clone the repository
git clone https://github.com/YOUR-USERNAME/secure-post-encryption-system-CSE447.git
cd secure-post-encryption-system-CSE447

Install dependencies
pip install -r requirements.txt

Create .env
MONGODB_URI=your_mongodb_connection_string

Run
python secure_app.py

Environment Variables

Use .env for private configuration and .env.example as a template.

Example .env.example:

MONGODB_URI=mongodb+srv://USERNAME:PASSWORD@YOUR-CLUSTER.mongodb.net/


Do not commit .env, database credentials, or aes_master.key to GitHub.

## Project Structure

```text
project/
├── secure_app.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
└── aes_master.key
```
Project

CSE447 Lab Project — Secure Authentication, Database Encryption and Post Encryption.
