import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime

# ====== Configuration ======
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5555
FORWARD_HOST = "127.0.0.1"
FORWARD_PORT = 6666

# ====== Simple GUI Logger ======
class MiddlemanGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Middleman Proxy 🕵️")
        self.root.geometry("700x500")
        self.root.configure(bg="#1E1E1E")

        self.text_area = scrolledtext.ScrolledText(
            root, wrap=tk.WORD, font=("Consolas", 10),
            bg="#252526", fg="#DCDCAA", insertbackground="white"
        )
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.text_area.insert(tk.END, f"[{timestamp}] {message}\n")
        self.text_area.see(tk.END)
        self.root.update()

# ====== Middleman Server ======
class MiddlemanProxy:
    def __init__(self, gui):
        self.gui = gui

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((LISTEN_HOST, LISTEN_PORT))
        server_socket.listen(5)
        self.gui.log(f"🕵️ Middleman started! Listening on port {LISTEN_PORT}")
        self.gui.log(f"Intercepting and forwarding to {FORWARD_HOST}:{FORWARD_PORT}")

        while True:
            client_conn, client_addr = server_socket.accept()
            self.gui.log(f"📥 Connection from client: {client_addr}")
            threading.Thread(target=self.handle_client, args=(client_conn,)).start()

    def handle_client(self, client_conn):
        try:
            forward_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            forward_socket.connect((FORWARD_HOST, FORWARD_PORT))
            threading.Thread(target=self.relay, args=(client_conn, forward_socket, "Client ➜ Server")).start()
            threading.Thread(target=self.relay, args=(forward_socket, client_conn, "Server ➜ Client")).start()
        except Exception as e:
            self.gui.log(f"❌ Error connecting to server: {e}")

    def relay(self, src, dst, direction):
        while True:
            try:
                data = src.recv(4096)
                if not data:
                    break
                self.gui.log(f"{direction}: {data.decode(errors='ignore')}")
                dst.sendall(data)
            except Exception:
                break
        src.close()
        dst.close()

# ====== Main ======
if __name__ == "__main__":
    root = tk.Tk()
    gui = MiddlemanGUI(root)

    proxy = MiddlemanProxy(gui)
    threading.Thread(target=proxy.start, daemon=True).start()

    root.mainloop()
