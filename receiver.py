import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import json
from datetime import datetime
from encryption_handler import EncryptionHandler


class ReceiverApp:
    def __init__(self, root):
        self.root = root
        self.root.title("📥 Secure Message Receiver (Server)")
        self.root.geometry("700x750")
        self.root.configure(bg='#2c3e50')

        self.encryption_handler = EncryptionHandler()
        self.server_socket = None
        self.is_listening = False

        self.create_widgets()

    def create_widgets(self):
        # Title
        title_label = tk.Label(
            self.root,
            text="📥 MESSAGE RECEIVER",
            font=('Arial', 24, 'bold'),
            bg='#2c3e50',
            fg='#e67e22'
        )
        title_label.pack(pady=20)

        # Config Frame
        config_frame = tk.LabelFrame(
            self.root,
            text="Server Configuration",
            font=('Arial', 12, 'bold'),
            bg='#34495e',
            fg='#ecf0f1',
            padx=15,
            pady=15
        )
        config_frame.pack(padx=20, pady=10, fill='x')

        # IP
        tk.Label(config_frame, text="Host IP:", font=('Arial', 11),
                 bg='#34495e', fg='#ecf0f1').grid(row=0, column=0, sticky='w', padx=5, pady=5)

        self.ip_entry = tk.Entry(config_frame, font=('Arial', 11), width=18)
        self.ip_entry.insert(0, "0.0.0.0")  # Listen on all interfaces
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)

        # Port
        tk.Label(config_frame, text="Port:", font=('Arial', 11),
                 bg='#34495e', fg='#ecf0f1').grid(row=0, column=2, sticky='w', padx=5, pady=5)

        self.port_entry = tk.Entry(config_frame, font=('Arial', 11), width=10)
        self.port_entry.insert(0, "5555")
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)

        # Key
        tk.Label(config_frame, text="Decryption Key:",
                 font=('Arial', 11), bg='#34495e', fg='#ecf0f1').grid(row=1, column=0, sticky='w', padx=5, pady=5)

        self.key_entry = tk.Entry(config_frame, font=('Arial', 11), width=25, show='*')
        self.key_entry.insert(0, "")
        self.key_entry.grid(row=1, column=1, columnspan=3, sticky='w', padx=5, pady=5)

        # Start/Stop Buttons
        button_frame = tk.Frame(config_frame, bg='#34495e')
        button_frame.grid(row=2, column=0, columnspan=4, pady=10)

        self.start_btn = tk.Button(
            button_frame,
            text="▶ START RECEIVER",
            bg='#27ae60',
            fg='white',
            font=('Arial', 12, 'bold'),
            padx=20,
            pady=8,
            command=self.start_server
        )
        self.start_btn.pack(side='left', padx=10)

        self.stop_btn = tk.Button(
            button_frame,
            text="⏹ STOP RECEIVER",
            bg='#c0392b',
            fg='white',
            font=('Arial', 12, 'bold'),
            padx=20,
            pady=8,
            command=self.stop_server,
            state='disabled'
        )
        self.stop_btn.pack(side='left', padx=10)

        # Log Frame
        log_frame = tk.LabelFrame(
            self.root,
            text="Incoming Message Log",
            font=('Arial', 12, 'bold'),
            bg='#34495e',
            fg='#ecf0f1',
            padx=15,
            pady=15
        )
        log_frame.pack(padx=20, pady=10, fill='both', expand=True)

        self.log_display = scrolledtext.ScrolledText(
            log_frame,
            height=20,
            width=60,
            font=('Courier', 10),
            wrap=tk.WORD,
            bg='#ecf0f1'
        )
        self.log_display.pack(fill='both', expand=True)

    # ------------------------
    # SERVER THREAD FUNCTIONS
    # ------------------------
    def start_server(self):
        if self.is_listening:
            messagebox.showinfo("Info", "Server is already running.")
            return

        try:
            ip = self.ip_entry.get()
            port = int(self.port_entry.get())

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((ip, port))
            self.server_socket.listen(5)
            self.is_listening = True

            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')

            self.log_message(f"✅ Receiver started on {ip}:{port}")
            threading.Thread(target=self.accept_connections, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {e}")
            self.log_message(f"❌ Failed to start server: {e}")

    def stop_server(self):
        self.is_listening = False
        try:
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
            self.log_message("🛑 Receiver stopped.")
        except Exception as e:
            self.log_message(f"❌ Error stopping server: {e}")

    def accept_connections(self):
        while self.is_listening:
            try:
                conn, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
            except Exception:
                break  # socket closed

    def handle_client(self, conn, addr):
        try:
            data = conn.recv(4096).decode('utf-8')
            if not data:
                return

            msg = json.loads(data)
            sender = msg.get('sender', 'Unknown')
            algorithm = msg.get('algorithm', 'Unknown')
            encrypted_message = msg.get('encrypted_message', '')
            timestamp = msg.get('timestamp', '')

            # Log received encrypted message
            self.log_message(
                f"📩 Encrypted message received from {sender}\n"
                f"Algorithm: {algorithm}\n"
                f"Encrypted Data: {encrypted_message[:80]}..."
            )

            # Decrypt message
            key = self.key_entry.get()
            try:
                decrypted_message = self.encryption_handler.decrypt(encrypted_message, algorithm, key)
                self.log_message(
                    f"🔓 Decrypted message from {sender}:\n{decrypted_message}\n"
                    f"Received at: {timestamp}"
                )
                conn.send(b"Message received and decrypted successfully.")
            except Exception as e:
                self.log_message(f"❌ Decryption failed: {e}")
                conn.send(f"Decryption error: {e}".encode())

        except Exception as e:
            self.log_message(f"❌ Error handling client: {e}")
        finally:
            conn.close()

    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_display.insert(tk.END, f"[{timestamp}] {message}\n{'-'*60}\n\n")
        self.log_display.see(tk.END)


def main():
    root = tk.Tk()
    app = ReceiverApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
