import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from encrypt_decrypt import encrypt_file, decrypt_file
import os
import subprocess
import platform

class FileEncryptorApp:
    def __init__(self, master):
        self.master = master
        master.title("Cifrador / Descifrador de Archivos")
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

        self.notebook.add(self.tab_intro, text='📝 Instrucciones')
        self.notebook.add(self.tab_encrypt, text='🔒 Cifrar')
        self.notebook.add(self.tab_decrypt, text='🔓 Descifrar')
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

        label = tk.Label(frame, text="Bienvenido", font=("Segoe UI", 16, "bold"), bg="#f9f9f9")
        label.pack(anchor='w')

        desc = (
            "Este programa permite proteger tus archivos de manera segura:\n\n"
            "Cifrado: Usa contraseña + AES para proteger un archivo.\n"
            "Descifrado: Recupera el archivo original si ingresas la contraseña correcta.\n"
            "Seguridad: Se usa PBKDF2 para derivar la clave y SHA-256 para verificar integridad.\n\n"
            "Puedes arrastrar y soltar archivos o usar Ctrl+V para pegar rutas."
        )
        desc_label = tk.Label(frame, text=desc, font=("Segoe UI", 11), bg="#f9f9f9")
        desc_label.pack(anchor='w', pady=10)

        self.history_label = tk.Label(frame, text="🕘 Historial de archivos:", font=("Segoe UI", 12, "bold"), bg="#f9f9f9")
        self.history_label.pack(anchor='w', pady=(10, 0))
        self.history_list = tk.Listbox(frame, height=5, font=("Segoe UI", 9))
        self.history_list.pack(fill='x')
        self.history_list.bind('<Double-Button-1>', self.open_file_location)

    def setup_encrypt_tab(self):
        frame = tk.Frame(self.tab_encrypt, bg="#f9f9f9")
        frame.pack(fill='both', expand=True)

        label = tk.Label(frame, text="🔒 Cifrado de archivo", font=("Segoe UI", 14, "bold"), bg="#f9f9f9")
        label.pack(pady=(20, 10))

        self.encrypt_button = tk.Button(
            frame,
            text="Seleccionar archivo y cifrar",
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
            text="ℹ️ El archivo cifrado se guardará con extensión .enc en la misma carpeta.",
            font=("Segoe UI", 9),
            bg="#f9f9f9",
            fg="#555555"
        )
        note_label.pack(pady=(5, 0))

    def setup_decrypt_tab(self):
        frame = tk.Frame(self.tab_decrypt, bg="#f9f9f9")
        frame.pack(fill='both', expand=True)

        label = tk.Label(frame, text="🔓 Descifrado de archivo", font=("Segoe UI", 14, "bold"), bg="#f9f9f9")
        label.pack(pady=(20, 10))

        self.decrypt_button = tk.Button(
            frame,
            text="Seleccionar archivo y descifrar",
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
            text="ℹ️ El archivo descifrado se guardará en la misma carpeta con su formato original.",
            font=("Segoe UI", 9),
            bg="#f9f9f9",
            fg="#555555"
        )
        note_label.pack(pady=(5, 0))

    def ask_validated_password(self):
        popup = tk.Toplevel(self.master)
        popup.title("Contraseña")
        popup.geometry("300x150")
        popup.transient(self.master)
        popup.grab_set()

        label = tk.Label(popup, text="Introduce la contraseña:", font=("Segoe UI", 10))
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
                strength_label.config(text="Fortaleza: Débil", fg="red")
            elif any(c.isdigit() for c in pw) and any(c.isupper() for c in pw) and any(c in '!@#$%^&*' for c in pw):
                strength_label.config(text="Fortaleza: Fuerte", fg="green")
            else:
                strength_label.config(text="Fortaleza: Media", fg="orange")

        pw_var.trace_add('write', check_strength)

        result = {'password': None}

        def submit():
            pw = pw_var.get()
            if len(pw) < 6:
                messagebox.showwarning("Contraseña débil", "La contraseña debe tener al menos 6 caracteres.", parent=popup)
            else:
                result['password'] = pw
                popup.destroy()

        button = tk.Button(popup, text="Aceptar", command=submit)
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
            messagebox.showinfo("✅ Éxito", f"Archivo cifrado en:\n{output_path}")
            self.add_to_history(output_path)
        except Exception as e:
            messagebox.showerror("❌ Error", str(e))

    def decrypt_file(self, file_path):
        password = self.ask_validated_password()
        if not password:
            return
        try:
            output_path = decrypt_file(file_path, password)
            messagebox.showinfo("✅ Éxito", f"Archivo descifrado en:\n{output_path}")
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
                messagebox.showerror("Error", f"No se pudo abrir la carpeta:\n{e}")
