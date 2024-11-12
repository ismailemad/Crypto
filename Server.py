import socket
import threading
import os
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import hashlib


# Generate RSA keys for digital signature
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


# Encrypt message using AES
def aes_encrypt(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message) + encryptor.finalize()
    return encrypted_message


# Decrypt message using AES
def aes_decrypt(encrypted_message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message


# Hash message using SHA-256
def sha256_hash(message):
    hash_object = hashlib.sha256()
    hash_object.update(message)
    return hash_object.digest()


# Sign message hash using RSA private key
def sign_message(private_key, message_hash):
    signature = private_key.sign(
        message_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


# Handle client connections
def handle_client(client_socket, log_widget):
    try:
        request = client_socket.recv(4096).decode()
        if request.startswith("SEND"):
            _, message = request.split(":", 1)
            message = message.encode()

            aes_key = os.urandom(32)  # AES-256 key
            iv = os.urandom(16)       # Initialization Vector

            encrypted_message = aes_encrypt(message, aes_key, iv)
            message_hash = sha256_hash(message)
            signature = sign_message(private_key, message_hash)

            with open("messages.txt", "a") as file:
                file.write("Original Message: " + message.decode() + "\n")
                file.write("Encrypted Message: " + encrypted_message.hex() + "\n")
                file.write("AES Key: " + aes_key.hex() + "\n")
                file.write("IV: " + iv.hex() + "\n")
                file.write("Message Hash: " + message_hash.hex() + "\n")
                file.write("Signature: " + signature.hex() + "\n")
                file.write("-" * 50 + "\n")

            log_widget.insert(tk.END, f"Message encrypted and stored: {message.decode()}\n")
            client_socket.send(b"Message encrypted and stored successfully.")

        elif request == "DECRYPT":
            with open("messages.txt", "r") as file:
                lines = file.readlines()

            blocks = "".join(lines).split("-" * 50)
            if len(blocks) < 2:
                client_socket.send(b"No messages to decrypt.")
                return

            last_block = blocks[-2].strip().splitlines()
            encrypted_message_hex = next(line.split(": ")[1] for line in last_block if "Encrypted Message" in line)
            aes_key_hex = next(line.split(": ")[1] for line in last_block if "AES Key" in line)
            iv_hex = next(line.split(": ")[1] for line in last_block if "IV" in line)

            encrypted_message = bytes.fromhex(encrypted_message_hex)
            aes_key = bytes.fromhex(aes_key_hex)
            iv = bytes.fromhex(iv_hex)

            decrypted_message = aes_decrypt(encrypted_message, aes_key, iv)
            log_widget.insert(tk.END, f"Message decrypted: {decrypted_message.decode()}\n")
            client_socket.send(decrypted_message)

    except Exception as e:
        client_socket.send(f"Error: {str(e)}".encode())
    finally:
        client_socket.close()


# Start the server
def start_server(log_widget):
    def server_thread():
        server.bind(("0.0.0.0", 9999))
        server.listen(5)
        log_widget.insert(tk.END, "Server is listening on port 9999...\n")
        while True:
            client_socket, addr = server.accept()
            log_widget.insert(tk.END, f"Accepted connection from {addr}\n")
            client_handler = threading.Thread(target=handle_client, args=(client_socket, log_widget))
            client_handler.start()

    threading.Thread(target=server_thread, daemon=True).start()


# GUI setup
private_key, public_key = generate_keys()
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

root = tk.Tk()
root.title("Server")

log = ScrolledText(root, width=80, height=20)
log.pack()

start_button = tk.Button(root, text="Start Server", command=lambda: start_server(log))
start_button.pack()

root.mainloop()
