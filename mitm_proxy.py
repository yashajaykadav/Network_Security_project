import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import socket
import threading
import json
from datetime import datetime
from encryption_handler import EncryptionHandler


class MITMProxyServer:
    def __init__(self, root):
        self.root = root
        self.root.title("🕵️ MITM Proxy Server - Advanced")
        self.root.geometry("1400x850")
        self.root.configure(bg='#0d1117')
        
        self.proxy_socket = None
        self.is_running = False
        self.encryption_handler = EncryptionHandler()
        self.intercepted_count = 0
        self.modified_count = 0
        
        self.create_widgets()
    
    def create_widgets(self):
        # Main Title Bar
        title_frame = tk.Frame(self.root, bg='#0d1117')
        title_frame.pack(pady=10, fill='x')
        
        title_label = tk.Label(
            title_frame,
            text="🕵️  MAN-IN-THE-MIDDLE PROXY SERVER",
            font=('Arial', 22, 'bold'),
            bg='#0d1117',
            fg='#ff4757'
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="⚠️ Security Testing & Message Interception Tool ⚠️",
            font=('Arial', 10, 'italic'),
            bg='#0d1117',
            fg='#ffa502'
        )
        subtitle_label.pack()
        
        # Statistics Panel (Full Width)
        stats_frame = tk.Frame(self.root, bg='#161b22', relief='ridge', bd=2)
        stats_frame.pack(padx=15, pady=8, fill='x')
        
        self.status_label = tk.Label(
            stats_frame,
            text="⚫ STATUS: OFFLINE",
            font=('Arial', 12, 'bold'),
            bg='#161b22',
            fg='#ff4757'
        )
        self.status_label.pack(side='left', padx=20, pady=10)
        
        self.intercept_count_label = tk.Label(
            stats_frame,
            text="📊 Intercepted: 0",
            font=('Arial', 11),
            bg='#161b22',
            fg='#2ed573'
        )
        self.intercept_count_label.pack(side='left', padx=15, pady=10)
        
        self.modified_count_label = tk.Label(
            stats_frame,
            text="✏️ Modified: 0",
            font=('Arial', 11),
            bg='#161b22',
            fg='#ffa502'
        )
        self.modified_count_label.pack(side='left', padx=15, pady=10)
        
        # TWO-COLUMN LAYOUT CONTAINER
        main_container = tk.Frame(self.root, bg='#0d1117')
        main_container.pack(fill='both', expand=True, padx=15, pady=10)
        
        # Configure grid weights for responsive layout
        main_container.grid_columnconfigure(0, weight=2, minsize=500)  # Left column (controls)
        main_container.grid_columnconfigure(1, weight=3, minsize=700)  # Right column (log)
        main_container.grid_rowconfigure(0, weight=1)
        
        # ==================== LEFT COLUMN: CONTROLS ====================
        left_panel = tk.Frame(main_container, bg='#0d1117')
        left_panel.grid(row=0, column=0, sticky='nsew', padx=(0, 10))
        
        # Create scrollable frame for left panel
        left_canvas = tk.Canvas(left_panel, bg='#0d1117', highlightthickness=0)
        left_scrollbar = tk.Scrollbar(left_panel, orient="vertical", command=left_canvas.yview)
        scrollable_left = tk.Frame(left_canvas, bg='#0d1117')
        
        scrollable_left.bind(
            "<Configure>",
            lambda e: left_canvas.configure(scrollregion=left_canvas.bbox("all"))
        )
        
        left_canvas.create_window((0, 0), window=scrollable_left, anchor="nw")
        left_canvas.configure(yscrollcommand=left_scrollbar.set)
        
        left_canvas.pack(side="left", fill="both", expand=True)
        left_scrollbar.pack(side="right", fill="y")
        
        # Mousewheel binding
        def _on_mousewheel(event):
            left_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        left_canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # === Config Frame ===
        config_frame = tk.LabelFrame(
            scrollable_left,
            text="⚙️ Proxy Configuration",
            font=('Arial', 11, 'bold'),
            bg='#161b22',
            fg='#58a6ff',
            padx=15,
            pady=12
        )
        config_frame.pack(fill='x', pady=(0, 10))
        
        # Proxy Listen Settings
        tk.Label(config_frame, text="🔌 Proxy Listen IP:", font=('Arial', 9, 'bold'),
                 bg='#161b22', fg='#c9d1d9').grid(row=0, column=0, sticky='w', padx=5, pady=8)
        
        self.proxy_ip_entry = tk.Entry(config_frame, font=('Arial', 9), width=15, 
                                       bg='#0d1117', fg='#c9d1d9', insertbackground='white')
        self.proxy_ip_entry.insert(0, "0.0.0.0")
        self.proxy_ip_entry.grid(row=0, column=1, padx=5, pady=8, sticky='ew')
        
        tk.Label(config_frame, text="Port:", font=('Arial', 9, 'bold'),
                 bg='#161b22', fg='#c9d1d9').grid(row=1, column=0, sticky='w', padx=5, pady=8)
        
        self.proxy_port_entry = tk.Entry(config_frame, font=('Arial', 9), width=15,
                                         bg='#0d1117', fg='#c9d1d9', insertbackground='white')
        self.proxy_port_entry.insert(0, "4444")
        self.proxy_port_entry.grid(row=1, column=1, padx=5, pady=8, sticky='ew')
        
        # Target Receiver Settings
        tk.Label(config_frame, text="🎯 Target Receiver IP:", font=('Arial', 9, 'bold'),
                 bg='#161b22', fg='#c9d1d9').grid(row=2, column=0, sticky='w', padx=5, pady=8)
        
        self.target_ip_entry = tk.Entry(config_frame, font=('Arial', 9), width=15,
                                        bg='#0d1117', fg='#c9d1d9', insertbackground='white')
        self.target_ip_entry.insert(0, "127.0.0.1")
        self.target_ip_entry.grid(row=2, column=1, padx=5, pady=8, sticky='ew')
        
        tk.Label(config_frame, text="Port:", font=('Arial', 9, 'bold'),
                 bg='#161b22', fg='#c9d1d9').grid(row=3, column=0, sticky='w', padx=5, pady=8)
        
        self.target_port_entry = tk.Entry(config_frame, font=('Arial', 9), width=15,
                                          bg='#0d1117', fg='#c9d1d9', insertbackground='white')
        self.target_port_entry.insert(0, "5555")
        self.target_port_entry.grid(row=3, column=1, padx=5, pady=8, sticky='ew')
        
        config_frame.grid_columnconfigure(1, weight=1)
        
        # Control Buttons
        button_frame = tk.Frame(config_frame, bg='#161b22')
        button_frame.grid(row=4, column=0, columnspan=2, pady=12)
        
        self.start_btn = tk.Button(
            button_frame,
            text="▶ START",
            bg='#238636',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=20,
            pady=8,
            command=self.start_proxy,
            cursor='hand2',
            relief='raised',
            bd=3,
            width=10
        )
        self.start_btn.grid(row=0, column=0, padx=5, pady=5)
        
        self.stop_btn = tk.Button(
            button_frame,
            text="⏹ STOP",
            bg='#da3633',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=20,
            pady=8,
            command=self.stop_proxy,
            state='disabled',
            cursor='hand2',
            relief='raised',
            bd=3,
            width=10
        )
        self.stop_btn.grid(row=0, column=1, padx=5, pady=5)
        
        clear_btn = tk.Button(
            button_frame,
            text="🗑️ CLEAR",
            bg='#6e7681',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=20,
            pady=8,
            command=self.clear_log,
            cursor='hand2',
            relief='raised',
            bd=3,
            width=10
        )
        clear_btn.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        
        # === Attack Options Frame ===
        attack_frame = tk.LabelFrame(
            scrollable_left,
            text="⚔️ Attack & Interception Options",
            font=('Arial', 11, 'bold'),
            bg='#161b22',
            fg='#ff4757',
            padx=15,
            pady=12
        )
        attack_frame.pack(fill='x', pady=(0, 10))
        
        # Mode selection
        self.attack_mode = tk.StringVar(value="passive")
        
        tk.Radiobutton(
            attack_frame,
            text="👁️ Passive Mode (Log Only)",
            variable=self.attack_mode,
            value="passive",
            bg='#161b22',
            fg='#2ed573',
            selectcolor='#161b22',
            font=('Arial', 9, 'bold'),
            command=self.update_attack_mode
        ).pack(anchor='w', pady=3)
        
        tk.Radiobutton(
            attack_frame,
            text="🔓 Active Mode (Decrypt & View)",
            variable=self.attack_mode,
            value="decrypt",
            bg='#161b22',
            fg='#ffa502',
            selectcolor='#161b22',
            font=('Arial', 9, 'bold'),
            command=self.update_attack_mode
        ).pack(anchor='w', pady=3)
        
        tk.Radiobutton(
            attack_frame,
            text="✏️ Attack Mode (Modify Messages)",
            variable=self.attack_mode,
            value="modify",
            bg='#161b22',
            fg='#ff4757',
            selectcolor='#161b22',
            font=('Arial', 9, 'bold'),
            command=self.update_attack_mode
        ).pack(anchor='w', pady=3)
        
        # === Decryption Key Frame ===
        self.key_frame = tk.LabelFrame(
            scrollable_left,
            text="🔑 Decryption Key",
            bg='#161b22',
            fg='#58a6ff',
            font=('Arial', 10, 'bold'),
            padx=12,
            pady=10
        )
        
        key_inner = tk.Frame(self.key_frame, bg='#161b22')
        key_inner.pack(fill='x')
        
        self.key_entry = tk.Entry(
            key_inner,
            font=('Arial', 9),
            show='*',
            bg='#0d1117',
            fg='#c9d1d9',
            insertbackground='white'
        )
        self.key_entry.pack(fill='x', pady=5)
        
        self.show_key_var = tk.BooleanVar()
        tk.Checkbutton(
            key_inner,
            text="Show Key",
            variable=self.show_key_var,
            bg='#161b22',
            fg='#c9d1d9',
            selectcolor='#161b22',
            command=lambda: self.key_entry.config(show='' if self.show_key_var.get() else '*')
        ).pack(anchor='w')
        
        # === Modification Panel ===
        self.modify_frame = tk.LabelFrame(
            scrollable_left,
            text="✏️ Message Modification Settings",
            bg='#161b22',
            fg='#ff4757',
            font=('Arial', 10, 'bold'),
            padx=12,
            pady=10
        )
        
        tk.Label(
            self.modify_frame,
            text="Find Text:",
            bg='#161b22',
            fg='#c9d1d9',
            font=('Arial', 9, 'bold')
        ).pack(anchor='w', pady=(5, 2))
        
        self.find_entry = tk.Entry(
            self.modify_frame,
            font=('Arial', 9),
            bg='#0d1117',
            fg='#c9d1d9',
            insertbackground='white'
        )
        self.find_entry.pack(fill='x', pady=(0, 10))
        
        tk.Label(
            self.modify_frame,
            text="Replace With:",
            bg='#161b22',
            fg='#c9d1d9',
            font=('Arial', 9, 'bold')
        ).pack(anchor='w', pady=(5, 2))
        
        self.replace_entry = tk.Entry(
            self.modify_frame,
            font=('Arial', 9),
            bg='#0d1117',
            fg='#c9d1d9',
            insertbackground='white'
        )
        self.replace_entry.pack(fill='x', pady=(0, 5))
        
        # Initially hide advanced panels
        self.key_frame.pack_forget()
        self.modify_frame.pack_forget()
        
        # ==================== RIGHT COLUMN: LOG DISPLAY ====================
        right_panel = tk.Frame(main_container, bg='#0d1117')
        right_panel.grid(row=0, column=1, sticky='nsew')
        
        # Log Display
        log_frame = tk.LabelFrame(
            right_panel,
            text="📋 Intercepted Messages Log",
            font=('Arial', 12, 'bold'),
            bg='#161b22',
            fg='#58a6ff',
            padx=12,
            pady=12
        )
        log_frame.pack(fill='both', expand=True)
        
        # Text widget with scrollbars
        text_container = tk.Frame(log_frame, bg='#0d1117')
        text_container.pack(fill='both', expand=True)
        
        self.log_text = tk.Text(
            text_container,
            font=('Consolas', 9),
            wrap=tk.WORD,
            bg='#0d1117',
            fg='#2ed573',
            insertbackground='white',
            selectbackground='#1f6feb',
            selectforeground='white'
        )
        
        # Vertical scrollbar
        v_scrollbar = tk.Scrollbar(text_container, orient=tk.VERTICAL, command=self.log_text.yview)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=v_scrollbar.set)
        
        # Horizontal scrollbar
        h_scrollbar = tk.Scrollbar(text_container, orient=tk.HORIZONTAL, command=self.log_text.xview)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.log_text.config(xscrollcommand=h_scrollbar.set)
        
        self.log_text.pack(side=tk.LEFT, fill='both', expand=True)
        
        # Configure text tags for colored output
        self.log_text.tag_config("error", foreground="#ff4757")
        self.log_text.tag_config("success", foreground="#2ed573")
        self.log_text.tag_config("warning", foreground="#ffa502")
        self.log_text.tag_config("info", foreground="#58a6ff")
        self.log_text.tag_config("modified", foreground="#ff6348", background="#2d0d0d")
        self.log_text.tag_config("header", foreground="#ffffff", font=('Consolas', 10, 'bold'))
        
        # Initial welcome message
        self.log("=" * 90, "info")
        self.log("🕵️  MITM PROXY SERVER INITIALIZED", "success", "header")
        self.log("=" * 90, "info")
        self.log("📌 Configure proxy settings and select attack mode to begin", "info")
        self.log("🔒 All interception activities will be logged here\n", "info")
    
    def update_attack_mode(self):
        mode = self.attack_mode.get()
        
        if mode == "passive":
            self.key_frame.pack_forget()
            self.modify_frame.pack_forget()
        elif mode == "decrypt":
            self.key_frame.pack(fill='x', pady=(0, 10))
            self.modify_frame.pack_forget()
        elif mode == "modify":
            self.key_frame.pack(fill='x', pady=(0, 10))
            self.modify_frame.pack(fill='x', pady=(0, 10))
    
    def clear_log(self):
        self.log_text.delete('1.0', tk.END)
        self.intercepted_count = 0
        self.modified_count = 0
        self.update_stats()
        self.log("🗑️ Log cleared\n", "warning")
    
    def update_stats(self):
        self.intercept_count_label.config(text=f"📊 Intercepted: {self.intercepted_count}")
        self.modified_count_label.config(text=f"✏️ Modified: {self.modified_count}")
    
    def start_proxy(self):
        if self.is_running:
            messagebox.showinfo("Info", "Proxy is already running.")
            return
        
        try:
            proxy_ip = self.proxy_ip_entry.get()
            proxy_port = int(self.proxy_port_entry.get())
            
            self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.proxy_socket.bind((proxy_ip, proxy_port))
            self.proxy_socket.listen(5)
            
            self.is_running = True
            self.start_btn.config(state='disabled', bg='#6e7681')
            self.stop_btn.config(state='normal', bg='#da3633')
            
            self.status_label.config(text="🟢 STATUS: ACTIVE", fg='#2ed573')
            
            self.log(f"\n{'═'*90}", "success")
            self.log(f"✅ MITM Proxy started on {proxy_ip}:{proxy_port}", "success", "header")
            self.log(f"🎯 Forwarding to {self.target_ip_entry.get()}:{self.target_port_entry.get()}", "info")
            self.log(f"⚔️ Attack mode: {self.attack_mode.get().upper()}", "warning")
            self.log(f"{'═'*90}\n", "success")
            
            threading.Thread(target=self.accept_connections, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start proxy: {e}")
            self.log(f"❌ Error: {e}", "error")
    
    def stop_proxy(self):
        self.is_running = False
        try:
            if self.proxy_socket:
                self.proxy_socket.close()
                self.proxy_socket = None
            
            self.start_btn.config(state='normal', bg='#238636')
            self.stop_btn.config(state='disabled', bg='#6e7681')
            self.status_label.config(text="⚫ STATUS: OFFLINE", fg='#ff4757')
            
            self.log("\n🛑 Proxy stopped.\n", "warning", "header")
        except Exception as e:
            self.log(f"❌ Error stopping proxy: {e}", "error")
    
    def accept_connections(self):
        while self.is_running:
            try:
                client_conn, client_addr = self.proxy_socket.accept()
                threading.Thread(
                    target=self.handle_client,
                    args=(client_conn, client_addr),
                    daemon=True
                ).start()
            except Exception:
                break
    
    def handle_client(self, client_conn, client_addr):
        try:
            # Receive data from sender
            data = client_conn.recv(4096).decode('utf-8')
            if not data:
                return
            
            self.intercepted_count += 1
            self.root.after(0, self.update_stats)
            
            self.log(f"\n{'═'*90}", "info")
            self.log(f"📨 INTERCEPTED MESSAGE #{self.intercepted_count} from {client_addr[0]}:{client_addr[1]}", "warning", "header")
            self.log(f"{'═'*90}", "info")
            
            # Parse JSON
            msg_data = json.loads(data)
            sender = msg_data.get('sender', 'Unknown')
            algorithm = msg_data.get('algorithm', 'Unknown')
            encrypted_msg = msg_data.get('encrypted_message', '')
            timestamp = msg_data.get('timestamp', '')
            
            # Log intercepted metadata
            self.log(f"👤 Sender: {sender}", "info")
            self.log(f"🔐 Algorithm: {algorithm}", "info")
            self.log(f"🕐 Timestamp: {timestamp}", "info")
            self.log(f"📝 Encrypted Payload: {encrypted_msg[:80]}...", "info")
            
            mode = self.attack_mode.get()
            modified = False
            
            # DECRYPT MODE or MODIFY MODE
            if mode in ["decrypt", "modify"]:
                key = self.key_entry.get()
                if key:
                    try:
                        # Decrypt the message
                        decrypted_msg = self.encryption_handler.decrypt(
                            encrypted_msg, 
                            algorithm, 
                            key
                        )
                        self.log(f"\n🔓 DECRYPTED MESSAGE:", "success")
                        self.log(f"   {decrypted_msg}", "success")
                        
                        # MODIFY MODE - Actually change the message
                        if mode == "modify":
                            find_text = self.find_entry.get()
                            replace_text = self.replace_entry.get()
                            
                            if find_text and find_text in decrypted_msg:
                                # Modify the decrypted message
                                modified_msg = decrypted_msg.replace(find_text, replace_text)
                                
                                # Re-encrypt the modified message
                                new_encrypted = self.encryption_handler.encrypt(
                                    modified_msg,
                                    algorithm,
                                    key
                                )
                                
                                # Update the message data
                                msg_data['encrypted_message'] = new_encrypted
                                encrypted_msg = new_encrypted
                                modified = True
                                self.modified_count += 1
                                self.root.after(0, self.update_stats)
                                
                                self.log(f"\n✏️ MESSAGE MODIFIED!", "modified", "modified")
                                self.log(f"   Original: {decrypted_msg}", "warning")
                                self.log(f"   Modified: {modified_msg}", "modified")
                                self.log(f"   Re-encrypted: {new_encrypted[:80]}...", "modified")
                            else:
                                self.log(f"\n⚠️ No match found for '{find_text}' in message", "warning")
                        
                    except Exception as e:
                        self.log(f"\n❌ Decryption failed: {e}", "error")
                        self.log(f"   (Wrong key or algorithm mismatch)", "error")
                else:
                    self.log(f"\n⚠️ No decryption key provided", "warning")
            
            # Forward to actual receiver
            target_ip = self.target_ip_entry.get()
            target_port = int(self.target_port_entry.get())
            
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(5)
            target_socket.connect((target_ip, target_port))
            
            # Send (possibly modified) data
            target_socket.send(json.dumps(msg_data).encode('utf-8'))
            
            # Get response from receiver
            response = target_socket.recv(1024).decode('utf-8')
            target_socket.close()
            
            status = "🔴 MODIFIED & FORWARDED" if modified else "📬 FORWARDED"
            self.log(f"\n{status} to {target_ip}:{target_port}", "success" if not modified else "modified")
            self.log(f"💬 Receiver Response: {response}", "info")
            self.log(f"{'═'*90}\n", "info")
            
            # Send response back to sender
            client_conn.send(response.encode('utf-8'))
            
        except Exception as e:
            self.log(f"❌ Proxy error: {e}", "error")
            try:
                client_conn.send(f"Proxy error: {e}".encode())
            except:
                pass
        finally:
            client_conn.close()
    
    def log(self, message, color="info", tag=None):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", tag if tag else color)
        self.log_text.see(tk.END)
        self.log_text.update_idletasks()


def main():
    root = tk.Tk()
    app = MITMProxyServer(root)
    root.mainloop()


if __name__ == "__main__":
    main()
