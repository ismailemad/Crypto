import socket

def send_message_to_server(message):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 9999))  # Replace with server IP if running remotely
    client.send(f"SEND:{message}".encode())
    response = client.recv(4096)
    print(response.decode())
    client.close()

def request_decryption_from_server():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 9999))  # Replace with server IP if running remotely
    client.send("DECRYPT".encode())
    response = client.recv(4096)
    print("Decrypted Message:", response.decode())
    client.close()

# Client interaction
print("1. Send a message to encrypt")
print("2. Decrypt the last message")
choice = input("Enter your choice: ")

if choice == "1":
    message = input("Enter the message: ")
    send_message_to_server(message)
elif choice == "2":
    request_decryption_from_server()
else:
    print("Invalid choice.")