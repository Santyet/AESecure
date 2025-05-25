import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from encrypt_decrypt import encrypt_file, decrypt_file
import os
import subprocess
import platform

class FileEncryptorApp:
    def __init__(self, master):
        self.master = master
        master.title("File Encryptor / Decryptor")
        master.geometry("630x450")
        master.configure(bg="#f9f9f9")

        self.history = []
        self.drag_file_path = None

        style = ttk.Style()
        style.configure("TNotebook.Tab", padding=[10, 5], font=("Segoe UI", 11))
        style.configure("TButton", font=("Segoe UI", 10), padding=6)

        self.notebook = ttk.Notebook(master)
        self.tab_intro = ttk.Frame(self.notebook)
        self.tab_encrypt = ttk.Frame(self.notebook)
        self.tab_decrypt = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_intro, text='📝 Instructions')
        self.notebook.add(self.tab_encrypt, text='🔒 Encrypt')
        self.notebook.add(self.tab_decrypt, text='🔓 Decrypt')
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        self.setup_intro_tab()
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()

        master.bind('<Control-v>', self.handle_paste)
        master.drop_target_register('*')
        master.dnd_bind('<<Drop>>', self.handle_drop)

    def setup_intro_tab(self):
        frame = tk.Frame(self.tab_intro, bg="#f9f9f9")
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        label = tk.Label(frame, text="Welcome", font=("Segoe UI", 16, "bold"), bg="#f9f9f9")
        label.pack(anchor='w')

        desc = (
            "This program allows you to securely protect your files:\n\n"
            "Encryption: Uses password + AES to protect a file.\n"
            "Decryption: Recovers the original file with the correct password.\n"
            "Security: PBKDF2 is used to derive the key and SHA-256 for integrity verification.\n\n"
            "You can drag and drop files or use Ctrl+V to paste paths."
        )
        desc_label = tk.Label(frame, text=desc, font=("Segoe UI", 11), bg="#f9f9f9")
        desc_label.pack(anchor='w', pady=10)

        self.history_label = tk.Label(frame, text="🕘 File history:", font=("Segoe UI", 12, "bold"), bg="#f9f9f9")
        self.history_label.pack(anchor='w', pady=(10, 0))
        self.history_list = tk.Listbox(frame, height=5, font=("Segoe UI", 9))
        self.history_list.pack(fill='x')
        self.history_list.bind('<Double-Button-1>', self.open_file_location)

    def setup_encrypt_tab(self):
        frame = tk.Frame(self.tab_encrypt, bg="#f9f9f9")
        frame.pack(fill='both', expand=True)

        label = tk.Label(frame, text="🔒 File Encryption", font=("Segoe UI", 14, "bold"), bg="#f9f9f9")
        label.pack(pady=(20, 10))

        self.encrypt_button = tk.Button(
            frame,
            text="Select file and encrypt",
            bg="#0066cc",
            fg="white",
            font=("Segoe UI", 11),
            command=self.select_and_encrypt,
            padx=20,
            pady=10
        )
        self.encrypt_button.pack(pady=10)

        note_label = tk.Label(
            frame,
            text="ℹ️ The encrypted file will be saved with .enc extension in the same folder.",
            font=("Segoe UI", 9),
            bg="#f9f9f9",
            fg="#555555"
        )
        note_label.pack(pady=(5, 0))

    def setup_decrypt_tab(self):
        frame = tk.Frame(self.tab_decrypt, bg="#f9f9f9")
        frame.pack(fill='both', expand=True)

        label = tk.Label(frame, text="🔓 File Decryption", font=("Segoe UI", 14, "bold"), bg="#f9f9f9")
        label.pack(pady=(20, 10))

        self.decrypt_button = tk.Button(
            frame,
            text="Select file and decrypt",
            bg="#28a745",
            fg="white",
            font=("Segoe UI", 11),
            command=self.select_and_decrypt,
            padx=20,
            pady=10
        )
        self.decrypt_button.pack(pady=10)

        note_label = tk.Label(
            frame,
            text="ℹ️ The decrypted file will be saved in the same folder with its original format.",
            font=("Segoe UI", 9),
            bg="#f9f9f9",
            fg="#555555"
        )
        note_label.pack(pady=(5, 0))

    def ask_validated_password(self):
        popup = tk.Toplevel(self.master)
        popup.title("Password")
        popup.geometry("300x150")
        popup.transient(self.master)
        popup.grab_set()

        label = tk.Label(popup, text="Enter your password:", font=("Segoe UI", 10))
        label.pack(pady=(10, 5))

        pw_var = tk.StringVar()
        entry = tk.Entry(popup, textvariable=pw_var, show='*', width=30)
        entry.pack(pady=5)
        entry.focus()

        strength_label = tk.Label(popup, text="", font=("Segoe UI", 9))
        strength_label.pack(pady=2)

        def check_strength(*_):
            pw = pw_var.get()
            if len(pw) < 6:
                strength_label.config(text="Strength: Weak", fg="red")
            elif any(c.isdigit() for c in pw) and any(c.isupper() for c in pw) and any(c in '!@#$%^&*' for c in pw):
                strength_label.config(text="Strength: Strong", fg="green")
            else:
                strength_label.config(text="Strength: Medium", fg="orange")

        pw_var.trace_add('write', check_strength)

        result = {'password': None}

        def submit():
            pw = pw_var.get()
            if len(pw) < 6:
                messagebox.showwarning("Weak password", "Password must be at least 6 characters long.", parent=popup)
            else:
                result['password'] = pw
                popup.destroy()

        button = tk.Button(popup, text="OK", command=submit)
        button.pack(pady=10)

        self.master.wait_window(popup)
        return result['password']

    def select_and_encrypt(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        self.encrypt_file(file_path)

    def select_and_decrypt(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        self.decrypt_file(file_path)

    def encrypt_file(self, file_path):
        password = self.ask_validated_password()
        if not password:
            return
        try:
            output_path = encrypt_file(file_path, password)
            messagebox.showinfo("✅ Success", f"File encrypted at:\n{output_path}")
            self.add_to_history(output_path)
        except Exception as e:
            messagebox.showerror("❌ Error", str(e))

    def decrypt_file(self, file_path):
        password = self.ask_validated_password()
        if not password:
            return
        try:
            output_path = decrypt_file(file_path, password)
            messagebox.showinfo("✅ Success", f"File decrypted at:\n{output_path}")
            self.add_to_history(output_path)
        except Exception as e:
            messagebox.showerror("❌ Error", str(e))

    def add_to_history(self, path):
        if path not in self.history:
            self.history.insert(0, path)
            self.history = self.history[:5]
            self.update_history_listbox()

    def update_history_listbox(self):
        if hasattr(self, 'history_list'):
            self.history_list.delete(0, tk.END)
            for item in self.history:
                self.history_list.insert(tk.END, item)

    def handle_paste(self, event):
        try:
            clipboard = self.master.clipboard_get()
            if os.path.exists(clipboard):
                self.encrypt_file(clipboard)
        except Exception:
            pass

    def handle_drop(self, event):
        path = event.data.strip('{').strip('}')
        if os.path.isfile(path):
            self.encrypt_file(path)

    def open_file_location(self, event):
        selection = self.history_list.curselection()
        if selection:
            file_path = self.history_list.get(selection[0])
            folder = os.path.dirname(file_path)
            try:
                if platform.system() == "Windows":
                    subprocess.run(['explorer', folder])
                elif platform.system() == "Darwin":
                    subprocess.run(['open', folder])
                else:
                    subprocess.run(['xdg-open', folder])
            except Exception as e:
                messagebox.showerror("Error", f"Could not open folder:\n{e}")
