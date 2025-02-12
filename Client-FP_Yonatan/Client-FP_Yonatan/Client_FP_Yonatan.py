import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# Global variables for the chat client
client = None
client_id = None

class ProxyMonitorUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Proxy Server Dashboard")
        self.root.geometry("850x650")
        self.root.resizable(False, False)

        # Apply modern theme
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 11), padding=5)
        style.configure("TLabel", font=("Arial", 11))
        style.configure("TFrame", background="#f5f5f5")

        # Header
        header = ttk.Frame(root, padding=10)
        header.pack(fill="x")
        ttk.Label(header, text="🔐 Secure Proxy Server", font=("Arial", 16, "bold")).pack()

        # Tabs Navigation
        self.tabs = ttk.Frame(root)
        self.tabs.pack(fill="x", pady=5)
        self.create_tabs()

        # Content Area
        self.content_frame = ttk.Frame(root, padding=10)
        self.content_frame.pack(fill="both", expand=True)

        self.show_dashboard()  # Default tab

    def create_tabs(self):
        """Create tab navigation buttons"""
        ttk.Button(self.tabs, text="📊 Dashboard", command=self.show_dashboard, width=15).pack(side="left", padx=5)
        ttk.Button(self.tabs, text="⚠️ Threat Detection", command=self.show_threats, width=15).pack(side="left", padx=5)
        ttk.Button(self.tabs, text="⚙️ Proxy Settings", command=self.show_settings, width=15).pack(side="left", padx=5)
        ttk.Button(self.tabs, text="💬 Chat", command=self.show_chat, width=15).pack(side="left", padx=5)
        ttk.Button(self.tabs, text="▶ Start Proxy", command=self.start_proxy, width=15, style="Start.TButton").pack(side="left", padx=5)
        ttk.Button(self.tabs, text="⏹ Stop Proxy", command=self.stop_proxy, width=15, style="Stop.TButton").pack(side="left", padx=5)

    def show_dashboard(self):
        """Display network traffic logs"""
        self.clear_frame()
        ttk.Label(self.content_frame, text="📊 Network Traffic Logs", font=("Arial", 12, "bold")).pack(pady=5)

        self.log_text = scrolledtext.ScrolledText(self.content_frame, width=100, height=20)
        self.log_text.pack(pady=5)
        self.log_text.insert(tk.END, "✅ Proxy started...\nMonitoring traffic...\n")

    def show_threats(self):
        """Display detected threats"""
        self.clear_frame()
        ttk.Label(self.content_frame, text="⚠️ Threat Detection", font=("Arial", 12, "bold")).pack(pady=5)

        self.threat_text = scrolledtext.ScrolledText(self.content_frame, width=100, height=20, fg="red")
        self.threat_text.pack(pady=5)
        self.threat_text.insert(tk.END, "🔍 No threats detected...\n")

    def show_settings(self):
        """Display proxy settings form"""
        self.clear_frame()
        ttk.Label(self.content_frame, text="⚙️ Proxy Settings", font=("Arial", 12, "bold")).pack(pady=5)

        form_frame = ttk.Frame(self.content_frame, padding=10)
        form_frame.pack()

        ttk.Label(form_frame, text="🔗 Proxy IP:").grid(row=0, column=0, padx=5, pady=5)
        self.proxy_ip_entry = ttk.Entry(form_frame, width=30)
        self.proxy_ip_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(form_frame, text="🔢 Port:").grid(row=1, column=0, padx=5, pady=5)
        self.proxy_port_entry = ttk.Entry(form_frame, width=10)
        self.proxy_port_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(form_frame, text="💾 Save Settings", command=self.save_settings).grid(row=2, columnspan=2, pady=10)

    def show_chat(self):
        """Display chat interface"""
        self.clear_frame()
        ttk.Label(self.content_frame, text="💬 Secure Chat", font=("Arial", 12, "bold")).pack(pady=5)

        global client_id_entry, chat_display, message_entry, connect_button, send_button

        frame = ttk.Frame(self.content_frame, padding=10)
        frame.pack()

        # Client ID Entry
        ttk.Label(frame, text="🆔 Your ID:").grid(row=0, column=0, padx=5, pady=5)
        client_id_entry = ttk.Entry(frame, width=20)
        client_id_entry.grid(row=0, column=1, padx=5, pady=5)

        # Connect Button
        connect_button = ttk.Button(frame, text="🔗 Connect", command=connect_to_server)
        connect_button.grid(row=0, column=2, padx=5, pady=5)

        # Chat Display
        chat_display = scrolledtext.ScrolledText(self.content_frame, width=100, height=20, state=tk.DISABLED)
        chat_display.pack(pady=5)

        # Message Entry
        message_entry = ttk.Entry(self.content_frame, width=80)
        message_entry.pack(side="left", padx=5, pady=5)

        # Send Button
        send_button = ttk.Button(self.content_frame, text="📨 Send", command=send_message)
        send_button.pack(side="left", padx=5, pady=5)
        send_button.config(state=tk.DISABLED)  # Disable until connected

    def save_settings(self):
        """Save proxy settings"""
        ip = self.proxy_ip_entry.get()
        port = self.proxy_port_entry.get()
        messagebox.showinfo("Settings Saved", f"✅ Proxy set to {ip}:{port}")

    def start_proxy(self):
        """Simulate starting the proxy"""
        messagebox.showinfo("Proxy Server", "✅ Proxy server started successfully!")
        self.log_text.insert(tk.END, "▶ Proxy is running...\n")

    def stop_proxy(self):
        """Simulate stopping the proxy"""
        messagebox.showwarning("Proxy Server", "⏹ Proxy server stopped.")
        self.log_text.insert(tk.END, "⏹ Proxy stopped.\n")

    def clear_frame(self):
        """Clear content frame"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()

def connect_to_server():
    """Connects client to the chat server"""
    global client, client_id

    client_id = client_id_entry.get().strip()
    if not client_id:
        messagebox.showerror("Error", "Please enter a client ID")
        return

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('localhost', 5000))

        threading.Thread(target=read_messages, daemon=True).start()
        connect_button.config(state=tk.DISABLED)
        send_button.config(state=tk.NORMAL)
        message_entry.config(state=tk.NORMAL)
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect: {e}")

def read_messages():
    """Handles incoming messages"""
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            if message:
                root.after(0, display_message, message)
        except:
            break

def display_message(message):
    """Updates chat display"""
    chat_display.config(state=tk.NORMAL)
    chat_display.insert(tk.END, f"{message}\n")
    chat_display.yview(tk.END)
    chat_display.config(state=tk.DISABLED)

def send_message():
    """Sends a message to the server"""
    message = message_entry.get().strip()
    if message:
        client.send(f"[{client_id}] {message}".encode('utf-8'))
        display_message(f"You: {message}")
        message_entry.delete(0, tk.END)

# Run Tkinter App
root = tk.Tk()
app = ProxyMonitorUI(root)
root.mainloop()
