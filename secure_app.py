#!/usr/bin/env python3
"""
CSE447 Lab Project - Secure Social Platform
Features: RSA encryption, password hashing, MongoDB storage, MAC verification
Modified to remove public user listing for privacy and add logout functionality.
Users must share usernames out-of-band to add as recipients.
"""

import os
import hashlib
import hmac
import base64
import json
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pymongo import MongoClient
import secrets
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class CryptoManager:
    """Handles all cryptographic operations"""
    
    def __init__(self):
        self.aes_key = self._load_or_generate_aes_key()
    
    def _load_or_generate_aes_key(self):
        """Load or generate AES key for database field encryption"""
        key_file = "aes_master.key"
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = os.urandom(32)  # 256-bit key
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    def generate_rsa_keypair(self):
        """Generate RSA key pair for user"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def rsa_encrypt(self, message, public_key_pem):
        """Encrypt message with RSA public key"""
        public_key = serialization.load_pem_public_key(public_key_pem)
        encrypted = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode('utf-8')
    
    def rsa_decrypt(self, encrypted_message, private_key_pem):
        """Decrypt message with RSA private key"""
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')
    
    def aes_encrypt(self, data):
        """Encrypt data with AES for database storage"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad data to 16-byte boundary
        padding_length = 16 - (len(data.encode('utf-8')) % 16)
        padded_data = data + chr(padding_length) * padding_length
        
        encrypted = encryptor.update(padded_data.encode('utf-8')) + encryptor.finalize()
        return base64.b64encode(iv + encrypted).decode('utf-8')
    
    def aes_decrypt(self, encrypted_data):
        """Decrypt AES encrypted data"""
        encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
        iv = encrypted_bytes[:16]
        encrypted = encrypted_bytes[16:]
        
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        
        # Remove padding
        padding_length = decrypted[-1]
        return decrypted[:-padding_length].decode('utf-8')
    
    def hash_password(self, password):
        """Hash password with SHA-256 and salt"""
        salt = secrets.token_bytes(32)
        password_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
        return base64.b64encode(salt).decode('utf-8'), password_hash
    
    def verify_password(self, password, salt_b64, stored_hash):
        """Verify password against stored hash"""
        salt = base64.b64decode(salt_b64.encode('utf-8'))
        password_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
        return password_hash == stored_hash
    
    def generate_mac(self, data):
        """Generate HMAC-SHA256 for integrity check"""
        return hmac.new(self.aes_key, data.encode('utf-8'), hashlib.sha256).hexdigest()
    
    def verify_mac(self, data, mac):
        """Verify HMAC-SHA256"""
        expected_mac = self.generate_mac(data)
        return hmac.compare_digest(expected_mac, mac)

class DatabaseManager:
    """Handles MongoDB operations"""
    
    def __init__(self):
        # Get MongoDB URI from environment variable
        MONGODB_URI = os.getenv('MONGODB_URI')
        
        if not MONGODB_URI:
            print("❌ Error: MONGODB_URI not found in environment variables")
            print("Please create a .env file with your MongoDB connection string")
            print("Example .env file content:")
            print("MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/")
            exit(1)
        
        try:
            self.client = MongoClient(MONGODB_URI)
            # Test the connection
            self.client.admin.command('ping')
            print("✅ Connected to MongoDB successfully!")
        except Exception as e:
            print(f"❌ MongoDB connection failed: {e}")
            print("Please check your MONGODB_URI in .env file and internet connection")
            exit(1)
            
        self.db = self.client['secure_social_db']
        self.users = self.db['users']
        self.posts = self.db['posts']
        self.crypto = CryptoManager()
    
    def create_user(self, username, email, password):
        """Create new user with encrypted data"""
        if self.users.find_one({"username": username}):
            return False, "Username already exists"
        
        # Hash password
        salt, password_hash = self.crypto.hash_password(password)
        
        # Generate RSA key pair
        private_key, public_key = self.crypto.generate_rsa_keypair()
        
        # Encrypt sensitive data
        encrypted_email = self.crypto.aes_encrypt(email)
        encrypted_private_key = self.crypto.aes_encrypt(private_key.decode('utf-8'))
        
        # Generate MAC for integrity
        user_data = f"{username}{email}"
        mac = self.crypto.generate_mac(user_data)
        
        user_doc = {
            "username": username,
            "email_encrypted": encrypted_email,
            "password_salt": salt,
            "password_hash": password_hash,
            "private_key_encrypted": encrypted_private_key,
            "public_key": public_key.decode('utf-8'),
            "mac": mac,
            "created_at": datetime.utcnow()
        }
        
        try:
            self.users.insert_one(user_doc)
            return True, "User created successfully"
        except Exception as e:
            return False, f"Database error: {str(e)}"
    
    def authenticate_user(self, username, password):
        """Authenticate user credentials"""
        user = self.users.find_one({"username": username})
        if not user:
            return False, None
        
        # Verify password
        if self.crypto.verify_password(password, user['password_salt'], user['password_hash']):
            # Decrypt and return user data
            email = self.crypto.aes_decrypt(user['email_encrypted'])
            private_key = self.crypto.aes_decrypt(user['private_key_encrypted'])
            
            # Verify integrity
            user_data = f"{username}{email}"
            if self.crypto.verify_mac(user_data, user['mac']):
                return True, {
                    'username': username,
                    'email': email,
                    'private_key': private_key,
                    'public_key': user['public_key']
                }
            else:
                return False, None
        
        return False, None
    
    def create_post(self, author, content, recipients, author_private_key):
        """Create encrypted post for specific recipients only"""
        
        # Validate recipients exist
        valid_recipients = []
        for recipient in recipients:
            user = self.users.find_one({"username": recipient})
            if user:
                valid_recipients.append({
                    'username': recipient,
                    'public_key': user['public_key']
                })
            else:
                print(f"Warning: User '{recipient}' not found, skipping...")
        
        if not valid_recipients:
            return False, "No valid recipients found"
        
        # Encrypt content ONLY for specified recipients + author
        encrypted_content = {}
        
        # Encrypt for author (so they can see their own post)
        author_user = self.users.find_one({"username": author})
        if author_user:
            try:
                encrypted_for_author = self.crypto.rsa_encrypt(content, author_user['public_key'].encode('utf-8'))
                encrypted_content[author] = encrypted_for_author
            except Exception as e:
                print(f"Error encrypting for author {author}: {e}")
        
        # Encrypt for each specified recipient
        for recipient in valid_recipients:
            try:
                encrypted_for_user = self.crypto.rsa_encrypt(content, recipient['public_key'].encode('utf-8'))
                encrypted_content[recipient['username']] = encrypted_for_user
            except Exception as e:
                print(f"Error encrypting for user {recipient['username']}: {e}")
        
        # Generate MAC for post integrity
        recipients_list = ','.join([r['username'] for r in valid_recipients])
        post_data = f"{author}{content}{recipients_list}"
        mac = self.crypto.generate_mac(post_data)
        
        post_doc = {
            "author": author,
            "recipients": [r['username'] for r in valid_recipients],  # Store recipient list
            "encrypted_content": encrypted_content,
            "mac": mac,
            "created_at": datetime.utcnow()
        }
        
        try:
            result = self.posts.insert_one(post_doc)
            return True, f"Post created for {len(valid_recipients)} recipients"
        except Exception as e:
            return False, f"Database error: {str(e)}"
    
    def get_posts_for_user(self, username, user_private_key):
        """Get and decrypt posts for specific user (only posts they have access to)"""
        # Only get posts where user is in the recipients list OR is the author
        posts = self.posts.find({
            "$or": [
                {"recipients": username},  # User is in recipient list
                {"author": username}       # User is the author
            ]
        }).sort("created_at", -1)
        
        decrypted_posts = []
        
        for post in posts:
            try:
                # Check if user has access to this post
                if username in post['encrypted_content']:
                    encrypted_content = post['encrypted_content'][username]
                    decrypted_content = self.crypto.rsa_decrypt(encrypted_content, user_private_key.encode('utf-8'))
                    
                    # Verify MAC
                    recipients_list = ','.join(post.get('recipients', []))
                    post_data = f"{post['author']}{decrypted_content}{recipients_list}"
                    if self.crypto.verify_mac(post_data, post['mac']):
                        decrypted_posts.append({
                            'author': post['author'],
                            'content': decrypted_content,
                            'recipients': post.get('recipients', []),
                            'created_at': post['created_at']
                        })
                    else:
                        print(f"MAC verification failed for post from {post['author']}")
                else:
                    # User doesn't have access to this post - skip silently
                    continue
            except Exception as e:
                print(f"Error decrypting post: {e}")
        
        return decrypted_posts

class SecureSocialApp:
    """Main application class"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.current_user = None
    
    def register(self, username, email, password):
        """Register new user"""
        return self.db.create_user(username, email, password)
    
    def login(self, username, password):
        """Login user"""
        success, user_data = self.db.authenticate_user(username, password)
        if success:
            self.current_user = user_data
        return success, user_data
    
    def logout(self):
        """Logout current user"""
        if self.current_user:
            self.current_user = None
            return True, "Logged out successfully"
        return False, "No user is currently logged in"
    
    def post(self, content, recipients):
        """Create new post for specific recipients"""
        if not self.current_user:
            return False, "Not authenticated"
        
        if not recipients:
            return False, "No recipients specified"
        
        return self.db.create_post(
            self.current_user['username'], 
            content,
            recipients,
            self.current_user['private_key']
        )
    
    def view_posts(self):
        """View all posts for current user (only posts they have access to)"""
        if not self.current_user:
            return []
        
        return self.db.get_posts_for_user(
            self.current_user['username'], 
            self.current_user['private_key']
        )

def main():
    """Simple CLI interface for testing"""
    app = SecureSocialApp()
    
    print("=== Secure Social Platform ===")
    
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Post to Specific Users (requires login)")
        print("4. View My Posts (requires login)")
        print("5. Logout")
        print("6. Exit")
        
        choice = input("Choose option: ")
        
        if choice == '1':
            username = input("Username: ")
            email = input("Email: ")
            password = input("Password: ")
            
            success, message = app.register(username, email, password)
            print(f"Registration: {'Success' if success else 'Failed'} - {message}")
        
        elif choice == '2':
            username = input("Username: ")
            password = input("Password: ")
            
            success, user_data = app.login(username, password)
            if success:
                print(f"Login successful! Welcome {user_data['username']}")
            else:
                print("Login failed!")
        
        elif choice == '3':
            if not app.current_user:
                print("Please login first!")
                continue
            
            content = input("Post content: ")
            recipients_input = input("Recipients (comma-separated usernames): ")
            
            if not recipients_input.strip():
                print("No recipients specified!")
                continue
                
            recipients = [r.strip() for r in recipients_input.split(',')]
            
            success, message = app.post(content, recipients)
            print(f"Post: {'Success' if success else 'Failed'} - {message}")
        
        elif choice == '4':
            if not app.current_user:
                print("Please login first!")
                continue
            
            posts = app.view_posts()
            print(f"\n--- Your Posts ({len(posts)} found) ---")
            for post in posts:
                recipients = ', '.join(post.get('recipients', []))
                print(f"[{post['created_at']}] {post['author']} → [{recipients}]: {post['content']}")
        
        elif choice == '5':
            success, message = app.logout()
            print(message)
        
        elif choice == '6':
            break
        
        else:
            print("Invalid option!")

if __name__ == "__main__":
    main()