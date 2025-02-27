﻿import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# Global variables
server = None
clients = {}  # Dictionary to keep track of connected clients
client_id_counter = 0
lock = threading.Lock()
server_running = False

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🖥️ Secure Chat Server")
        self.root.geometry("700x500")
        self.root.resizable(False, False)

        # Header
        ttk.Label(root, text="🔐 Secure Chat Server", font=("Arial", 16, "bold")).pack(pady=10)

        # Server Control Buttons
        button_frame = ttk.Frame(root)
        button_frame.pack()

        self.start_button = ttk.Button(button_frame, text="▶ Start Server", command=self.start_server, width=15)
        self.start_button.grid(row=0, column=0, padx=5, pady=5)

        self.stop_button = ttk.Button(button_frame, text="⏹ Stop Server", command=self.stop_server, width=15, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5, pady=5)

        # Client List
        ttk.Label(root, text="👥 Connected Clients:", font=("Arial", 12, "bold")).pack(pady=5)
        self.client_listbox = tk.Listbox(root, width=50, height=5)
        self.client_listbox.pack(pady=5)

        # Disconnect Client Section
        disconnect_frame = ttk.Frame(root)
        disconnect_frame.pack(pady=5)

        ttk.Label(disconnect_frame, text="Client ID:").grid(row=0, column=0, padx=5)
        self.client_id_entry = ttk.Entry(disconnect_frame, width=10)
        self.client_id_entry.grid(row=0, column=1, padx=5)
        ttk.Button(disconnect_frame, text="❌ Disconnect", command=self.disconnect_selected_client).grid(row=0, column=2, padx=5)

        # Log Messages
        ttk.Label(root, text="📜 Server Logs:", font=("Arial", 12, "bold")).pack(pady=5)
        self.log_box = scrolledtext.ScrolledText(root, width=80, height=15, state=tk.DISABLED)
        self.log_box.pack(pady=5)

    def log_message(self, message):
        """Logs a message to the server GUI log box."""
        self.log_box.config(state=tk.NORMAL)
        self.log_box.insert(tk.END, message + "\n")
        self.log_box.yview(tk.END)
        self.log_box.config(state=tk.DISABLED)

    def start_server(self):
        """Starts the server and listens for connections."""
        global server, server_running, client_id_counter
        if server_running:
            messagebox.showinfo("Info", "Server is already running!")
            return

        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(('0.0.0.0', 5000))
            server.listen()
            server_running = True
            self.log_message("✅ Server started on port 5000")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

            # Start server in a separate thread
            threading.Thread(target=self.accept_clients, daemon=True).start()
        except Exception as e:
            self.log_message(f"❌ Error starting server: {e}")

    def accept_clients(self):
        """Accepts new client connections and assigns them unique IDs."""
        global client_id_counter
        while server_running:
            try:
                client_socket, client_address = server.accept()
                with lock:
                    client_id_counter += 1
                    client_id = client_id_counter
                    clients[client_id] = client_socket
                self.client_listbox.insert(tk.END, f"Client {client_id} - {client_address}")
                self.log_message(f"🔗 Client {client_id} connected from {client_address}")

                # Start thread to handle the client
                threading.Thread(target=self.handle_client, args=(client_socket, client_id), daemon=True).start()
            except Exception as e:
                self.log_message(f"❌ Error accepting client: {e}")

    def handle_client(self, client_socket, client_id):
        """Handles communication with a connected client."""
        while True:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if not message:
                    break
                self.log_message(f"📩 Received from Client {client_id}: {message}")

                # Private messaging
                if message.startswith("@"):
                    parts = message.split(":", 1)
                    if len(parts) >= 2 and parts[0][1:].isdigit():
                        recipient_id = int(parts[0][1:])
                        private_message = f"🔒 Private from {client_id}: {parts[1]}"
                        with lock:
                            recipient_client = clients.get(recipient_id)
                        if recipient_client:
                            recipient_client.sendall(private_message.encode('utf-8'))
                        else:
                            client_socket.sendall("❌ Recipient not found!".encode('utf-8'))
                else:
                    # Broadcast message to all clients
                    with lock:
                        for cid, c_socket in clients.items():
                            if cid != client_id:
                                c_socket.sendall(f"Client {client_id}: {message}".encode('utf-8'))
            except Exception as e:
                self.log_message(f"⚠️ Error with Client {client_id}: {e}")
                break
        self.disconnect_client(client_id)

    def disconnect_client(self, client_id):
        """Disconnects a client from the server."""
        with lock:
            client_socket = clients.pop(client_id, None)
        if client_socket:
            try:
                client_socket.close()
                self.log_message(f"❌ Client {client_id} disconnected.")
            except Exception as e:
                self.log_message(f"⚠️ Error closing Client {client_id}: {e}")

        # Remove from listbox
        for index, entry in enumerate(self.client_listbox.get(0, tk.END)):
            if entry.startswith(f"Client {client_id}"):
                self.client_listbox.delete(index)
                break

    def disconnect_selected_client(self):
        """Disconnects a client based on the entered client ID from the GUI."""
        try:
            client_id = int(self.client_id_entry.get())
            if client_id in clients:
                self.disconnect_client(client_id)
            else:
                messagebox.showerror("Error", "Client ID not found.")
        except ValueError:
            messagebox.showerror("Error", "Invalid Client ID.")

    def stop_server(self):
        """Stops the server and disconnects all clients."""
        global server_running
        if not server_running:
            return

        self.log_message("⏹ Stopping server...")

        # Disconnect all clients
        with lock:
            for client_id in list(clients.keys()):
                self.disconnect_client(client_id)

        # Stop the server
        try:
            server.close()
        except Exception as e:
            self.log_message(f"⚠️ Error stopping server: {e}")

        server_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log_message("🚫 Server stopped.")

# Run the GUI
root = tk.Tk()
app = ServerGUI(root)
root.mainloop()
