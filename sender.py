import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import json
from encryption_handler import EncryptionHandler
from datetime import datetime


class SenderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Message Sender (Client)")
        self.root.geometry("700x780")
        self.root.configure(bg='#2c3e50')

        self.encryption_handler = EncryptionHandler()
        self.create_widgets()

    def create_widgets(self):
        # Title
        title_label = tk.Label(
            self.root,
            text="📤 MESSAGE SENDER",
            font=('Arial', 24, 'bold'),
            bg='#2c3e50',
            fg='#3498db'
        )
        title_label.pack(pady=20)

        # Connection Configuration
        config_frame = tk.LabelFrame(
            self.root,
            text="Receiver Configuration",
            font=('Arial', 12, 'bold'),
            bg='#34495e',
            fg='#ecf0f1',
            padx=15,
            pady=15
        )
        config_frame.pack(padx=20, pady=10, fill='x')

        # Receiver IP
        tk.Label(
            config_frame,
            text="Receiver IP:",
            font=('Arial', 11),
            bg='#34495e',
            fg='#ecf0f1'
        ).grid(row=0, column=0, sticky='w', padx=5, pady=5)

        self.ip_entry = tk.Entry(config_frame, font=('Arial', 11), width=15)
        self.ip_entry.insert(0, "127.0.0.1")  # localhost
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)

        # Port
        tk.Label(
            config_frame,
            text="Port:",
            font=('Arial', 11),
            bg='#34495e',
            fg='#ecf0f1'
        ).grid(row=0, column=2, sticky='w', padx=5, pady=5)

        self.port_entry = tk.Entry(config_frame, font=('Arial', 11), width=10)
        self.port_entry.insert(0, "5555")
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)

        # Proxy controls (new)
        self.use_proxy_var = tk.BooleanVar(value=False)
        self.proxy_check = tk.Checkbutton(
            config_frame,
            text="Use Proxy (MITM)",
            variable=self.use_proxy_var,
            bg='#34495e',
            fg='#ecf0f1',
            selectcolor='#34495e',
            command=self.toggle_proxy_widgets
        )
        self.proxy_check.grid(row=1, column=0, sticky='w', padx=5, pady=8)

        tk.Label(
            config_frame,
            text="Proxy IP:",
            font=('Arial', 11),
            bg='#34495e',
            fg='#ecf0f1'
        ).grid(row=1, column=1, sticky='w', padx=5, pady=5)
        self.proxy_ip_entry = tk.Entry(config_frame, font=('Arial', 11), width=15)
        self.proxy_ip_entry.insert(0, "127.0.0.1")
        self.proxy_ip_entry.grid(row=1, column=2, padx=5, pady=5)

        tk.Label(
            config_frame,
            text="Proxy Port:",
            font=('Arial', 11),
            bg='#34495e',
            fg='#ecf0f1'
        ).grid(row=1, column=3, sticky='w', padx=5, pady=5)
        self.proxy_port_entry = tk.Entry(config_frame, font=('Arial', 11), width=8)
        self.proxy_port_entry.insert(0, "4444")
        self.proxy_port_entry.grid(row=1, column=4, padx=5, pady=5)

        # Sender Name
        tk.Label(
            config_frame,
            text="Your Name:",
            font=('Arial', 11),
            bg='#34495e',
            fg='#ecf0f1'
        ).grid(row=2, column=0, sticky='w', padx=5, pady=5)

        self.name_entry = tk.Entry(config_frame, font=('Arial', 11), width=20)
        self.name_entry.insert(0, "Anonymous")
        self.name_entry.grid(row=2, column=1, columnspan=3, sticky='w', padx=5, pady=5)

        # Message Frame
        message_frame = tk.LabelFrame(
            self.root,
            text="Compose Message",
            font=('Arial', 12, 'bold'),
            bg='#34495e',
            fg='#ecf0f1',
            padx=15,
            pady=15
        )
        message_frame.pack(padx=20, pady=10, fill='both', expand=True)

        # Original Message
        tk.Label(
            message_frame,
            text="Your Message:",
            font=('Arial', 11),
            bg='#34495e',
            fg='#ecf0f1'
        ).pack(anchor='w', pady=5)

        self.message_input = scrolledtext.ScrolledText(
            message_frame,
            height=6,
            width=60,
            font=('Arial', 11),
            wrap=tk.WORD
        )
        self.message_input.pack(fill='both', expand=True, pady=5)

        # Encryption Settings
        encryption_frame = tk.Frame(message_frame, bg='#34495e')
        encryption_frame.pack(fill='x', pady=10)

        # Algorithm Selection
        tk.Label(
            encryption_frame,
            text="Algorithm:",
            font=('Arial', 11),
            bg='#34495e',
            fg='#ecf0f1'
        ).pack(side='left', padx=5)

        self.algorithm_var = tk.StringVar()
        self.algorithm_combo = ttk.Combobox(
            encryption_frame,
            textvariable=self.algorithm_var,
            values=self.encryption_handler.get_available_algorithms(),
            state='readonly',
            font=('Arial', 10),
            width=15
        )
        # safety: if no algorithms available, set to empty string
        algs = self.encryption_handler.get_available_algorithms()
        if algs:
            self.algorithm_combo.current(0)
        else:
            self.algorithm_combo.set('')
        self.algorithm_combo.pack(side='left', padx=5)

        # Encryption Key
        tk.Label(
            encryption_frame,
            text="Key:",
            font=('Arial', 11),
            bg='#34495e',
            fg='#ecf0f1'
        ).pack(side='left', padx=5)

        self.key_input = tk.Entry(
            encryption_frame,
            font=('Arial', 11),
            width=20,
            show='*'
        )
        self.key_input.pack(side='left', padx=5)

        # Send Button
        send_btn = tk.Button(
            message_frame,
            text="🚀 ENCRYPT & SEND MESSAGE",
            command=self.send_message,
            bg='#27ae60',
            fg='white',
            font=('Arial', 13, 'bold'),
            padx=25,
            pady=12,
            cursor='hand2'
        )
        send_btn.pack(pady=15)

        # Status/Log Frame
        log_frame = tk.LabelFrame(
            self.root,
            text="Message Log",
            font=('Arial', 12, 'bold'),
            bg='#34495e',
            fg='#ecf0f1',
            padx=15,
            pady=15
        )
        log_frame.pack(padx=20, pady=10, fill='both', expand=True)

        self.log_display = scrolledtext.ScrolledText(
            log_frame,
            height=8,
            width=60,
            font=('Courier', 9),
            wrap=tk.WORD,
            bg='#ecf0f1'
        )
        self.log_display.pack(fill='both', expand=True)

        # Initialize proxy widgets state
        self.toggle_proxy_widgets()

    def toggle_proxy_widgets(self):
        state = 'normal' if self.use_proxy_var.get() else 'disabled'
        self.proxy_ip_entry.config(state=state)
        self.proxy_port_entry.config(state=state)

    def send_message(self):
        try:
            # Get all inputs
            message = self.message_input.get('1.0', tk.END).strip()
            if not message:
                messagebox.showwarning("Warning", "Please enter a message!")
                return

            # Determine destination: proxy or direct receiver
            use_proxy = self.use_proxy_var.get()
            if use_proxy:
                receiver_ip = self.proxy_ip_entry.get().strip()
                try:
                    receiver_port = int(self.proxy_port_entry.get().strip())
                except ValueError:
                    messagebox.showerror("Error", "Invalid proxy port.")
                    return
            else:
                receiver_ip = self.ip_entry.get().strip()
                try:
                    receiver_port = int(self.port_entry.get().strip())
                except ValueError:
                    messagebox.showerror("Error", "Invalid receiver port.")
                    return

            algorithm = self.algorithm_var.get()
            key = self.key_input.get()
            sender_name = self.name_entry.get()

            if not algorithm:
                messagebox.showerror("Error", "No encryption algorithm selected.")
                return

            # Encrypt message
            encrypted_message = self.encryption_handler.encrypt(message, algorithm, key)

            # Prepare data to send
            data = {
                'sender': sender_name,
                'algorithm': algorithm,
                'encrypted_message': encrypted_message,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            # Send via socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5)

            # Log where we're sending
            dest_label = f"proxy {receiver_ip}:{receiver_port}" if use_proxy else f"receiver {receiver_ip}:{receiver_port}"
            self.log_message(f"➡ Sending to {dest_label} ...")

            client_socket.connect((receiver_ip, receiver_port))
            client_socket.send(json.dumps(data).encode('utf-8'))

            # Receive acknowledgment
            response = client_socket.recv(1024).decode('utf-8')
            client_socket.close()

            # Log success
            self.log_message(
                f"✅ Message sent successfully!\n"
                f"To: {receiver_ip}:{receiver_port} (via {'Proxy' if use_proxy else 'Direct'})\n"
                f"Algorithm: {algorithm}\n"
                f"Original: {message}\n"
                f"Encrypted: {encrypted_message[:50]}...\n"
                f"Response: {response}"
            )

            messagebox.showinfo("Success", f"Message sent successfully!\n\n{response}")

            # Clear message input
            self.message_input.delete('1.0', tk.END)

        except socket.timeout:
            messagebox.showerror("Error", "Connection timeout! Make sure receiver/proxy is running.")
            self.log_message("❌ Connection timeout!")
        except ConnectionRefusedError:
            messagebox.showerror("Error", "Connection refused! Make sure receiver/proxy is running.")
            self.log_message("❌ Connection refused!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")
            self.log_message(f"❌ Error: {str(e)}")

    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_display.insert(tk.END, f"[{timestamp}] {message}\n{'-'*60}\n\n")
        self.log_display.see(tk.END)


def main():
    root = tk.Tk()
    app = SenderApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
