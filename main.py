from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os
import base64
import pyfiglet
from datetime import datetime
from prettytable import PrettyTable
import logging

# Constants
AES_KEY_SIZE = 32  # 256-bit AES Key
RSA_KEY_SIZE = 2048  # RSA Key size
HISTORY_FILE = "secure_communication_history.enc"
SALT_FILE = "salt.enc"
LOG_FILE = "system.log"

# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO)

# AES Encryption/Decryption Helpers
def load_or_create_salt():
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, 'rb') as f:
            return f.read()
    salt = os.urandom(16)
    with open(SALT_FILE, 'wb') as f:
        f.write(salt)
    return salt

def derive_aes_key(password):
    salt = load_or_create_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(key, ciphertext):
    decoded = base64.b64decode(ciphertext)
    iv, actual_ciphertext = decoded[:16], decoded[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(actual_ciphertext) + decryptor.finalize()

# RSA Key Generation and Handling
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_rsa_key(private_key, public_key, private_file="private_key.pem", public_file="public_key.pem", password=None):
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(private_file, 'wb') as priv_file, open(public_file, 'wb') as pub_file:
        priv_file.write(pem_private)
        pub_file.write(pem_public)
    logging.info(f"RSA keys saved to {private_file} and {public_file}")

def load_rsa_key(private_file="private_key.pem", public_file="public_key.pem", password=None):
    with open(private_file, 'rb') as priv_file, open(public_file, 'rb') as pub_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=password.encode() if password else None,
            backend=default_backend()
        )
        public_key = serialization.load_pem_public_key(
            pub_file.read(),
            backend=default_backend()
        )
    return private_key, public_key

def rsa_encrypt(public_key, message):
    return base64.b64encode(public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )).decode()

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        base64.b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

# Digital Signature Helpers
def sign_message(private_key, message):
    return base64.b64encode(private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )).decode()

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# History Handling with AES Encryption
def save_history(history, password):
    aes_key = derive_aes_key(password)
    data = '\n'.join(
        f"time: {record['time']} | operation: {record['operation']} | input: {record['input']} | result: {record['result']}"
        for record in history
    )
    with open(HISTORY_FILE, 'w') as file:
        file.write(aes_encrypt(aes_key, data))
    logging.info("Communication history saved securely.")

def load_history(password):
    if not os.path.exists(HISTORY_FILE):
        return []
    aes_key = derive_aes_key(password)
    with open(HISTORY_FILE, 'r') as file:
        encrypted_data = file.read()
        try:
            decrypted_bytes = aes_decrypt(aes_key, encrypted_data)
            data = decrypted_bytes.decode('utf-8')  # Decode bytes to string
        except (UnicodeDecodeError, ValueError):
            print("Failed to decrypt the history file. The file may be corrupted.")
            logging.error("Failed to decrypt history file.")
            return []
    history = []
    for line in data.split('\n'):
        parts = [part.split(': ')[1] for part in line.split(' | ')]
        history.append({
            'time': parts[0], 'operation': parts[1], 'input': parts[2], 'result': parts[3]
        })
    return history

def show_history(history):
    table = PrettyTable(["Time", "Operation", "Input", "Result"])
    for record in history:
        table.add_row([record['time'], record['operation'], record['input'], record['result']])
    print(table)

def clear_history():
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
        print("History cleared successfully.")
        logging.info("Communication history cleared.")
    else:
        print("No history to clear.")

# Main Program
def main():
    print(pyfiglet.figlet_format("Secret Ops System"))
    password = input("Set a secure password for session: ").strip()
    private_key, public_key = generate_rsa_key_pair()
    history = load_history(password)
    
    while True:
        print("\nMenu:")
        print("1. Send Encrypted Message")
        print("2. Receive Encrypted Message")
        print("3. View Communication History")
        print("4. Export Public Key")
        print("5. Clear Communication History")
        print("6. Exit")
        choice = input("Select an option (1-6): ").strip()

        if choice == '1':
            recipient_public_key = public_key  # Simulated exchange
            message = input("Enter message to send: ").strip()
            encrypted_message = rsa_encrypt(recipient_public_key, message)
            signature = sign_message(private_key, message)
            print(f"Encrypted Message: {encrypted_message}")
            print(f"Signature: {signature}")
            history.append({
                'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'operation': 'send',
                'input': message,
                'result': encrypted_message
            })
            logging.info(f"Sent message: {message}")

        elif choice == '2':
            encrypted_message = input("Enter received encrypted message: ").strip()
            sender_public_key = public_key  # Simulated exchange
            decrypted_message = rsa_decrypt(private_key, encrypted_message)
            signature = input("Enter sender's signature: ").strip()
            if verify_signature(sender_public_key, decrypted_message, signature):
                print(f"Decrypted Message: {decrypted_message}")
                print("Signature Verified: Message Integrity Confirmed")
                history.append({
                    'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'operation': 'receive',
                    'input': encrypted_message,
                    'result': decrypted_message
                })
            else:
                print("Invalid Signature: Message Tampered!")
                logging.warning("Invalid signature during message reception.")

        elif choice == '3':
            show_history(history)

        elif choice == '4':
            export_file = input("Enter the filename to export the public key: ").strip()
            save_rsa_key(private_key, public_key, private_file="private_key.pem", public_file=export_file)
            print(f"Public Key exported to {export_file}")
        
        elif choice == '5':
            clear_history()

        elif choice == '6':
            save_history(history, password)
            print("Session ended. History saved.")
            logging.info("Session ended and history saved.")
            break
        else:
            print("Invalid choice. Please select between 1-6.")

if __name__ == "__main__":
    main()
