import socket
import tkinter as tk


def send_message_to_server(message, log_widget):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", 9999))
        client.send(f"SEND:{message}".encode())
        response = client.recv(4096).decode()
        log_widget.insert(tk.END, f"Server: {response}\n")
        client.close()
    except Exception as e:
        log_widget.insert(tk.END, f"Error: {str(e)}\n")


def request_decryption_from_server(log_widget):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", 9999))
        client.send("DECRYPT".encode())
        response = client.recv(4096).decode()
        log_widget.insert(tk.END, f"Decrypted Message: {response}\n")
        client.close()
    except Exception as e:
        log_widget.insert(tk.END, f"Error: {str(e)}\n")


# GUI setup
root = tk.Tk()
root.title("Client")

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="Enter Message:").grid(row=0, column=0, padx=5)
message_entry = tk.Entry(frame, width=40)
message_entry.grid(row=0, column=1, padx=5)

log = tk.Text(root, width=80, height=20)
log.pack()

send_button = tk.Button(frame, text="Send", command=lambda: send_message_to_server(message_entry.get(), log))
send_button.grid(row=1, column=0, pady=5)

decrypt_button = tk.Button(frame, text="Decrypt", command=lambda: request_decryption_from_server(log))
decrypt_button.grid(row=1, column=1, pady=5)

root.mainloop()
