import sqlite3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet, InvalidToken
import bcrypt
import os
import pyperclip
import base64
import json
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from datetime import datetime, timedelta
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import re

class PasswordManager:
    def __init__(self, root):
        self.db_file = 'passwords.db'
        self.root = root
        self.master_password_hash, self.salt = self._load_or_create_master_password()
        self._initialize_database()
        self.login_attempts = 0
        self.MAX_LOGIN_ATTEMPTS = 3  # حداکثر تعداد تلاش‌های ناموفق
        self.lockout_time = None  # زمان پایان قفل‌شدن
        self.lockout_durations = [180, 300, 600]  # زمان‌های قفل‌شدن به ثانیه (۳ دقیقه، ۵ دقیقه، ۱۰ دقیقه)
        
        # تنظیمات سیستم لاگ‌گیری
        logging.basicConfig(filename='login_attempts.log', level=logging.INFO, 
                            format='%(asctime)s - %(message)s')
        
        # تولید کلیدها برای رمزنگاری ۴ لایه
        self.aes_key, self.aes_iv, self.private_key, self.public_key, self.fernet_key = generate_keys()

    def _derive_key(self, password, salt):
        """
        Derives a cryptographic key from the user's password and salt.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Set the key length to 32 bytes (256 bits)
            salt=salt,
            iterations=100_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _load_or_create_master_password(self):
        if os.path.exists('master_password.hash'):
            try:
                with open('master_password.hash', 'rb') as f:
                    data = f.read().split(b'::')
                    if len(data) != 2:
                        raise ValueError("Invalid master password file format.")
                    return data[0], data[1]  # master_password_hash و salt
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load master password: {e}")
                os.remove('master_password.hash')
                return self._load_or_create_master_password()
        else:
            master_password = set_master_password()
            if master_password:
                salt = os.urandom(16)  # تولید salt تصادفی
                hashed = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())
                with open('master_password.hash', 'wb') as f:
                    f.write(hashed + b'::' + salt)  # ذخیره hash و salt
                return hashed, salt
            else:
                self._exit_program()

    def _exit_program(self):
        messagebox.showinfo("Exit", "Program will now exit.")
        self.root.destroy()
        exit()

    def _verify_master_password(self):
        # بررسی آیا کاربر در حالت قفل‌شدن است
        if self.lockout_time and datetime.now() < self.lockout_time:
            remaining_time = (self.lockout_time - datetime.now()).seconds
            messagebox.showerror("Locked Out", f"Too many failed attempts. Please try again in {remaining_time} seconds.")
            logging.warning(f"User is locked out. Remaining time: {remaining_time} seconds.")
            return False

        master_password = simpledialog.askstring("Master Password", "Enter master password:", show='*')
        if (master_password and bcrypt.checkpw(master_password.encode(), self.master_password_hash)):
            try:
                self.key = self._derive_key(master_password, self.salt)
                self.login_attempts = 0  # ریست کردن شمارنده پس از ورود موفق
                self.lockout_time = None  # ریست کردن زمان قفل‌شدن
                logging.info("User logged in successfully.")
                return True
            except Exception as e:
                messagebox.showerror("Error", f"Failed to derive key: {e}")
                logging.error(f"Failed to derive key: {e}")
                return False
        else:
            self.login_attempts += 1
            logging.warning(f"Failed login attempt. Total attempts: {self.login_attempts}")
            if self.login_attempts >= self.MAX_LOGIN_ATTEMPTS:
                # محاسبه زمان قفل‌شدن
                lockout_duration = self.lockout_durations[min(len(self.lockout_durations) - 1, self.login_attempts // self.MAX_LOGIN_ATTEMPTS - 1)]
                self.lockout_time = datetime.now() + timedelta(seconds=lockout_duration)
                messagebox.showerror("Locked Out", f"Too many failed attempts. Please try again in {lockout_duration} seconds.")
                logging.warning(f"User locked out for {lockout_duration} seconds.")
            else:
                messagebox.showerror("Error", f"Incorrect master password. {self.MAX_LOGIN_ATTEMPTS - self.login_attempts} attempts remaining.")
            return False

    def _initialize_database(self):
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS seed_phrases (
                    id INTEGER PRIMARY KEY,
                    wallet_name TEXT NOT NULL,
                    seed_phrase TEXT NOT NULL
                )
            ''')
            conn.commit()

    def save_password(self, service, username, password):
        if not self._verify_master_password():
            return
        try:
            encrypted_password = multi_layer_encrypt(password.encode(), self.aes_key, self.aes_iv, self.public_key, self.fernet_key)
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO passwords (service, username, password)
                    VALUES (?, ?, ?)
                ''', (service, username, encrypted_password))
                conn.commit()
            messagebox.showinfo("Success", "Password saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password: {e}")

    def get_password(self, service):
        if not self._verify_master_password():
            return None, None
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT username, password FROM passwords WHERE service = ?
                ''', (service,))
                result = cursor.fetchone()
                if result:
                    username, encrypted_password = result
                    password = multi_layer_decrypt(encrypted_password, self.aes_key, self.aes_iv, self.private_key, self.fernet_key).decode()
                    return username, password
                return None, None
        except InvalidToken:
            messagebox.showerror("Error", "Failed to decrypt password. Master password may be incorrect.")
            return None, None
        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve password: {e}")
            return None, None

    def list_services(self):
        if not self._verify_master_password():
            return []
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT service FROM passwords')
                return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list services: {e}")
            return []

    def delete_password(self, service):
        if not self._verify_master_password():
            return
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM passwords WHERE service = ?', (service,))
                conn.commit()
            messagebox.showinfo("Success", "Password deleted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete password: {e}")

    def save_seed_phrase(self, wallet_name, seed_phrase):
        if not self._verify_master_password():
            return
        
        # بررسی تکراری بودن نام ولت
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT wallet_name FROM seed_phrases WHERE wallet_name = ?
                ''', (wallet_name,))
                result = cursor.fetchone()
                if result:
                    messagebox.showerror("Error", f"A wallet with the name '{wallet_name}' already exists!")
                    return
        except Exception as e:
            messagebox.showerror("Error", f"Failed to check for duplicate wallet: {e}")
            return

        # اگر ولت تکراری نبود، ذخیره‌سازی انجام می‌شود
        try:
            encrypted_seed_phrase = Fernet(self.key).encrypt(seed_phrase.encode())
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO seed_phrases (wallet_name, seed_phrase)
                    VALUES (?, ?)
                ''', (wallet_name, encrypted_seed_phrase))
                conn.commit()
            messagebox.showinfo("Success", "Seed phrase saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save seed phrase: {e}")

    def get_seed_phrase(self, wallet_name):
        if not self._verify_master_password():
            return None
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT seed_phrase FROM seed_phrases WHERE wallet_name = ?
                ''', (wallet_name,))
                result = cursor.fetchone()
                if result:
                    encrypted_seed_phrase = result[0]
                    seed_phrase = Fernet(self.key).decrypt(encrypted_seed_phrase).decode()
                    return seed_phrase
                return None
        except InvalidToken:
            messagebox.showerror("Error", "Failed to decrypt seed phrase. Master password may be incorrect.")
            return None
        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve seed phrase: {e}")
            return None

    def delete_seed_phrase(self, wallet_name):
        if not self._verify_master_password():
            return
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM seed_phrases WHERE wallet_name = ?', (wallet_name,))
                conn.commit()
            messagebox.showinfo("Success", "Seed phrase deleted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete seed phrase: {e}")

    def list_wallets(self):
        if not self._verify_master_password():
            return []
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT wallet_name FROM seed_phrases')
                return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list wallets: {e}")
            return []

    def import_backup(self, file_path):
        """
        واردات داده‌ها از یک فایل بک‌آپ رمزنگاری‌شده.
        """
        if not self._verify_master_password():
            return

        try:
            # درخواست رمز عبور برای رمزگشایی بک‌آپ
            password = simpledialog.askstring("Password", "Enter the password to decrypt the backup:", show='*')
            if not password:
                messagebox.showerror("Error", "Password is required to decrypt the backup.")
                return

            # خواندن نمک و داده‌های رمزنگاری‌شده از فایل
            with open(file_path, 'rb') as f:
                salt = f.read(16)  # 16 بایت اول نمک است
                encrypted_data = f.read()

            # تولید کلید از رمز عبور و نمک
            key = self._derive_key(password, salt)
            key = base64.urlsafe_b64decode(key)  # دیکد کردن کلید base64 به باینری

            # رمزگشایی داده‌ها
            decrypted_data = self._decrypt_aes(encrypted_data, key)

            # بررسی صحت داده‌های رمزگشایی‌شده
            try:
                backup_data = json.loads(decrypted_data.decode('utf-8'))
            except UnicodeDecodeError as e:
                logging.error(f"Failed to decode decrypted data: {e}")
                messagebox.showerror("Error", "Failed to decode backup data. Check the password and file integrity.")
                return None
            except json.JSONDecodeError as e:
                logging.error(f"Invalid JSON format: {e}")
                messagebox.showerror("Error", "Invalid backup data format.")
                return None

            # وارد کردن داده‌ها به دیتابیس
            self._import_backup_data(backup_data)

            messagebox.showinfo("Success", "Backup imported successfully!")
        except Exception as e:
            logging.error(f"Failed to import backup: {e}")
            messagebox.showerror("Error", f"Failed to import backup: {e}")

    def export_backup(self, file_path):
        """
    صادرات داده‌ها به یک فایل بک‌آپ رمزنگاری‌شده.
    """
        if not self._verify_master_password():
            return

        try:
            # دریافت داده‌ها از دیتابیس
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT service, username, password FROM passwords')
                passwords_data = cursor.fetchall()
                cursor.execute('SELECT wallet_name, seed_phrase FROM seed_phrases')
                seed_phrases_data = cursor.fetchall()

            # ساخت ساختار داده‌های بک‌آپ
            backup_data = {
                "passwords": [],
                "seed_phrases": []
            }

            # رمزگشایی و اضافه کردن رمزهای عبور به بک‌آپ
            for service, username, encrypted_password in passwords_data:
                try:
                    password = multi_layer_decrypt(encrypted_password, self.aes_key, self.aes_iv, self.private_key, self.fernet_key).decode()
                    backup_data["passwords"].append({
                        "service": service,
                        "username": username,
                        "password": password
                    })
                except Exception as e:
                    logging.error(f"Failed to decrypt password for service {service}: {e}")
                    continue

            # رمزگشایی و اضافه کردن عبارت‌های seed به بک‌آپ
            for wallet_name, encrypted_seed_phrase in seed_phrases_data:
                try:
                    seed_phrase = multi_layer_decrypt(encrypted_seed_phrase, self.aes_key, self.aes_iv, self.private_key, self.fernet_key).decode()
                    backup_data["seed_phrases"].append({
                        "wallet_name": wallet_name,
                        "seed_phrase": seed_phrase
                    })
                except Exception as e:
                    logging.error(f"Failed to decrypt seed phrase for wallet {wallet_name}: {e}")
                    continue

            # درخواست رمز عبور برای رمزنگاری بک‌آپ
            password = simpledialog.askstring("Password", "Enter a password to encrypt the backup:", show='*')
            if not password:
                messagebox.showerror("Error", "Password is required to encrypt the backup.")
                return

            # رمزنگاری داده‌های بک‌آپ
            salt = os.urandom(16)  # تولید نمک تصادفی
            key = self._derive_key(password, salt)  # تولید کلید از رمز عبور و نمک
            key = base64.urlsafe_b64decode(key)  # دیکد کردن کلید base64 به باینری
            encrypted_data = self._encrypt_aes(json.dumps(backup_data).encode(), key)

            # ذخیره‌سازی نمک و داده‌های رمزنگاری‌شده در فایل
            with open(file_path, 'wb') as f:
                f.write(salt + encrypted_data)

            messagebox.showinfo("Success", "Backup exported successfully!")
        except Exception as e:
            logging.error(f"Failed to export backup: {e}")
            messagebox.showerror("Error", f"Failed to export backup: {e}")

    def _import_backup_data(self, backup_data):
        """
        وارد کردن داده‌های بازیابی‌شده به دیتابیس.
        """
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()

                # اضافه کردن رمزهای عبور به دیتابیس
                for item in backup_data.get("passwords", []):
                    service = item["service"]
                    username = item["username"]
                    password = item["password"]

                    # بررسی تکراری بودن سرویس
                    cursor.execute('SELECT service FROM passwords WHERE service = ?', (service,))
                    existing_service = cursor.fetchone()

                    if existing_service:
                        # اگر سرویس تکراری وجود دارد، نام را تغییر دهید
                        counter = 1
                        new_service = f"{service}_{counter}"
                        while True:
                            cursor.execute('SELECT service FROM passwords WHERE service = ?', (new_service,))
                            if not cursor.fetchone():
                                break
                            counter += 1
                            new_service = f"{service}_{counter}"
                        service = new_service

                    # رمزنگاری و ذخیره‌سازی رمز عبور
                    encrypted_password = multi_layer_encrypt(password.encode(), self.aes_key, self.aes_iv, self.public_key, self.fernet_key)
                    cursor.execute('''
                        INSERT INTO passwords (service, username, password)
                        VALUES (?, ?, ?)
                    ''', (service, username, encrypted_password))

                # اضافه کردن عبارت‌های seed به دیتابیس
                for item in backup_data.get("seed_phrases", []):
                    wallet_name = item["wallet_name"]
                    seed_phrase = item["seed_phrase"]

                    # بررسی تکراری بودن ولت
                    cursor.execute('SELECT wallet_name FROM seed_phrases WHERE wallet_name = ?', (wallet_name,))
                    existing_wallet = cursor.fetchone()

                    if existing_wallet:
                        # اگر ولت تکراری وجود دارد، نام را تغییر دهید
                        counter = 1
                        new_wallet_name = f"{wallet_name}_{counter}"
                        while True:
                            cursor.execute('SELECT wallet_name FROM seed_phrases WHERE wallet_name = ?', (new_wallet_name,))
                            if not cursor.fetchone():
                                break
                            counter += 1
                            new_wallet_name = f"{wallet_name}_{counter}"
                        wallet_name = new_wallet_name

                    # رمزنگاری و ذخیره‌سازی عبارت seed
                    encrypted_seed_phrase = multi_layer_encrypt(seed_phrase.encode(), self.aes_key, self.aes_iv, self.public_key, self.fernet_key)
                    cursor.execute('''
                        INSERT INTO seed_phrases (wallet_name, seed_phrase)
                        VALUES (?, ?)
                    ''', (wallet_name, encrypted_seed_phrase))

                conn.commit()
        except Exception as e:
            logging.error(f"Failed to import backup data: {e}")
            raise e

    def _encrypt_aes(self, data, key):
        """
        داده‌ها را با استفاده از AES رمزنگاری می‌کند.
        """
        try:
            # Padding داده‌ها برای مطابقت با اندازه بلوک AES
            padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(data) + padder.finalize()

            # رمزنگاری داده‌ها با AES
            cipher = Cipher(algorithms.AES(key), modes.CFB(self.aes_iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            return encrypted_data
        except Exception as e:
            logging.error(f"Failed to encrypt data with AES: {e}")
            raise e

    def _decrypt_aes(self, encrypted_data, key):
        """
        داده‌های رمزنگاری‌شده با AES را رمزگشایی می‌کند.
        """
        try:
            # رمزگشایی داده‌ها با AES
            cipher = Cipher(algorithms.AES(key), modes.CFB(self.aes_iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # حذف Padding
            unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            return data
        except Exception as e:
            logging.error(f"Failed to decrypt data with AES: {e}")
            raise e

class PasswordManagerGUI:
    CONFIG_FILE = 'config.json'

    def __init__(self, root):
        self.root = root
        self.root.title("Nexopass")
        self.root.geometry("800x600")
        self.style = ttk.Style()
        self.manager = PasswordManager(self.root)

        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.load_config()
        self.create_widgets()
        self.create_menu()

        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_columnconfigure(2, weight=1)
        self.root.grid_columnconfigure(3, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_rowconfigure(3, weight=1)
        self.root.grid_rowconfigure(4, weight=1)

    def load_config(self):
        try:
            with open(self.CONFIG_FILE, 'r') as f:
                config = json.load(f)
                theme = config.get('theme', 'superhero')
                self.style.theme_use(theme)
                self.status_bar.config(text=f"{theme.capitalize()} Mode Activated")
        except FileNotFoundError:
            self.style.theme_use("superhero")
            self.status_bar.config(text="Dark Mode Activated")

    def save_config(self, theme):
        config = {'theme': theme}
        with open(self.CONFIG_FILE, 'w') as f:
            json.dump(config, f)

    def set_light_mode(self):
        self.style.theme_use("flatly")
        self.status_bar.config(text="Light Mode Activated")
        self.save_config("flatly")

    def set_dark_mode(self):
        self.style.theme_use("superhero")
        self.status_bar.config(text="Dark Mode Activated")
        self.save_config("superhero")

    def create_menu(self):
        # ایجاد منو
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # منوی File
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Backup", command=self.export_backup, accelerator="Ctrl+E")
        file_menu.add_command(label="Import Backup", command=self.import_backup, accelerator="Ctrl+I")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Ctrl+Q")

        # منوی Help
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

        # منوی Theme
        theme_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Theme", menu=theme_menu)
        theme_menu.add_command(label="Light Mode", command=self.set_light_mode, accelerator="Ctrl+L")
        theme_menu.add_command(label="Dark Mode", command=self.set_dark_mode, accelerator="Ctrl+D")

        # کلیدهای میانبر
        self.root.bind("<Control-e>", lambda event: self.export_backup())
        self.root.bind("<Control-i>", lambda event: self.import_backup())
        self.root.bind("<Control-q>", lambda event: self.root.quit())
        self.root.bind("<Control-l>", lambda event: self.set_light_mode())
        self.root.bind("<Control-d>", lambda event: self.set_dark_mode())

    def create_widgets(self):
        title_label = ttk.Label(self.root, text="Nexopass", font=("Helvetica", 24, "bold"))
        title_label.pack(pady=20)

        # Password Management Section
        password_frame = ttk.LabelFrame(self.root, text="Password Management", padding=10)
        password_frame.pack(pady=10, fill="x", padx=10)

        save_button = ttk.Button(password_frame, text="Save Password", command=self.save_password_dialog, bootstyle=SUCCESS)
        save_button.pack(side=LEFT, padx=5)

        retrieve_button = ttk.Button(password_frame, text="Retrieve Password", command=self.retrieve_password_dialog, bootstyle=INFO)
        retrieve_button.pack(side=LEFT, padx=5)

        delete_button = ttk.Button(password_frame, text="Delete Password", command=self.delete_password_dialog, bootstyle=DANGER)
        delete_button.pack(side=LEFT, padx=5)

        list_button = ttk.Button(password_frame, text="List Services", command=self.list_services_dialog, bootstyle=WARNING)
        list_button.pack(side=LEFT, padx=5)

        # Seed Phrase Management Section
        seed_phrase_frame = ttk.LabelFrame(self.root, text="Seed Phrase Management", padding=10)
        seed_phrase_frame.pack(pady=10, fill="x", padx=10)

        save_seed_button = ttk.Button(seed_phrase_frame, text="Save Seed Phrase", command=self.save_seed_phrase_dialog, bootstyle=SUCCESS)
        save_seed_button.pack(side=LEFT, padx=5)

        retrieve_seed_button = ttk.Button(seed_phrase_frame, text="Retrieve Seed Phrase", command=self.retrieve_seed_phrase_dialog, bootstyle=INFO)
        retrieve_seed_button.pack(side=LEFT, padx=5)

        delete_seed_button = ttk.Button(seed_phrase_frame, text="Delete Seed Phrase", command=self.delete_seed_phrase_dialog, bootstyle=DANGER)
        delete_seed_button.pack(side=LEFT, padx=5)

        list_wallets_button = ttk.Button(seed_phrase_frame, text="List Wallets", command=self.list_wallets_dialog, bootstyle=WARNING)
        list_wallets_button.pack(side=LEFT, padx=5)

        # Backup Management Section
        backup_frame = ttk.LabelFrame(self.root, text="Backup Management", padding=10)
        backup_frame.pack(pady=10, fill="x", padx=10)

        export_button = ttk.Button(backup_frame, text="Export Backup", command=self.export_backup, bootstyle=SECONDARY)
        export_button.pack(side=LEFT, padx=5)

        import_button = ttk.Button(backup_frame, text="Import Backup", command=self.import_backup, bootstyle=SECONDARY)
        import_button.pack(side=LEFT, padx=5)

        # نوار وضعیت
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def show_about(self):
        about_message = (
            "Password Manager v1.0\n"
            "Developed by MNSH\n"
            "Visit GitHub: https://github.com/Mashani1102"
        )
        messagebox.showinfo("About", about_message)

    def export_backup(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Binary files", "*.bin")])
        if file_path:
            self.manager.export_backup(file_path)

    def import_backup(self):
        file_path = filedialog.askopenfilename(filetypes=[("Binary files", "*.bin")])
        if file_path:
            self.manager.import_backup(file_path)

    def save_password_dialog(self):
        service = simpledialog.askstring("Service", "Enter service name:")
        username = simpledialog.askstring("Username", "Enter username:")
        password = simpledialog.askstring("Password", "Enter password:", show='*')
        if service and username and password:
            self.manager.save_password(service, username, password)

    def retrieve_password_dialog(self):
        service = simpledialog.askstring("Service", "Enter service name:")
        if service:
            username, password = self.manager.get_password(service)
            if username and password:
                self.show_password_details(service, username, password)
            else:
                messagebox.showerror("Error", "Service not found or incorrect master password.")

    def show_password_details(self, service, username, password):
        # ایجاد پنجره جدید برای نمایش جزئیات
        details_window = ttk.Toplevel(self.root)
        details_window.title(f"Password Details for {service}")
        details_window.geometry("400x200")

        # نمایش عنوان
        ttk.Label(details_window, text=f"Password Details for {service}:", font=("Helvetica", 14, "bold")).pack(pady=10)

        # نمایش یوزرنیم
        username_frame = ttk.Frame(details_window)
        username_frame.pack(pady=5, padx=10, fill="x")

        ttk.Label(username_frame, text="Username:", font=("Helvetica", 12)).pack(side=tk.LEFT)
        username_entry = ttk.Entry(username_frame, width=20, font=("Helvetica", 12))
        username_entry.insert(0, username)
        username_entry.config(state="readonly")  # غیرفعال کردن ویرایش
        username_entry.pack(side=tk.LEFT, padx=5)

        # دکمه کپی یوزرنیم
        copy_username_button = ttk.Button(username_frame, text="Copy", command=lambda: self.copy_to_clipboard(username), bootstyle=INFO)
        copy_username_button.pack(side=tk.LEFT, padx=5)

        # نمایش پسورد
        password_frame = ttk.Frame(details_window)
        password_frame.pack(pady=5, padx=10, fill="x")

        ttk.Label(password_frame, text="Password:", font=("Helvetica", 12)).pack(side=tk.LEFT)
        password_entry = ttk.Entry(password_frame, width=20, font=("Helvetica", 12))
        password_entry.insert(0, password)
        password_entry.config(state="readonly")  # غیرفعال کردن ویرایش
        password_entry.pack(side=tk.LEFT, padx=5)

        # دکمه کپی پسورد
        copy_password_button = ttk.Button(password_frame, text="Copy", command=lambda: self.copy_to_clipboard(password), bootstyle=INFO)
        copy_password_button.pack(side=tk.LEFT, padx=5)

        # دکمه بستن پنجره
        close_button = ttk.Button(details_window, text="Close", command=details_window.destroy, bootstyle=DANGER)
        close_button.pack(pady=20)

    def copy_to_clipboard(self, text):
        pyperclip.copy(text)  # کپی متن به کلیپ‌برد
        messagebox.showinfo("Copied", "Text copied to clipboard!")  # نمایش پیام تأیید

    def delete_password_dialog(self):
        service = simpledialog.askstring("Service", "Enter service name:")
        if service:
            self.manager.delete_password(service)

    def list_services_dialog(self):
        services = self.manager.list_services()
        self.show_list_window("Services", services)

    def save_seed_phrase_dialog(self):
        wallet_name = simpledialog.askstring("Wallet Name", "Enter wallet name:")
        if wallet_name:
            # پرسش از کاربر برای تعداد کلمات
            seed_length = simpledialog.askinteger("Seed Phrase Length", "Enter the number of words (12 or 24):", minvalue=12, maxvalue=24)
            if seed_length not in [12, 24]:
                messagebox.showerror("Error", "Seed phrase must be 12 or 24 words.")
                return

            seed_window = ttk.Toplevel(self.root)
            seed_window.title(f"Save Seed Phrase for {wallet_name}")
            seed_window.geometry("600x400")

            ttk.Label(seed_window, text=f"Enter your {seed_length}-word seed phrase:", font=("Helvetica", 12)).pack(pady=10)

            seed_entries = []
            frame = ttk.Frame(seed_window)
            frame.pack(pady=10)

            # تنظیم تعداد کلمات در هر ردیف
            words_per_row = 6 if seed_length == 12 else 8  # 12 کلمه در ۲ ردیف، ۲۴ کلمه در ۳ ردیف

            # ایجاد ورودی‌ها برای هر کلمه
            for i in range(seed_length):
                if i % words_per_row == 0:
                    row_frame = ttk.Frame(frame)
                    row_frame.pack()
                
                # ایجاد Entry با شماره پیش‌فرض
                entry = ttk.Entry(row_frame, width=10, font=("Helvetica", 12))
                entry.insert(0, str(i + 1))  # شماره‌گذاری از ۱ شروع می‌شود
                entry.config(foreground="gray")  # رنگ متن پیش‌فرض خاکستری
                entry.pack(side=tk.LEFT, padx=5, pady=5)
                seed_entries.append(entry)

                # اضافه کردن رویداد FocusIn برای پاک کردن متن پیش‌فرض
                entry.bind("<FocusIn>", lambda event, e=entry, se=seed_entries: self.clear_default_text(e, se))

            def save_seed():
                seed_phrase = " ".join(entry.get() for entry in seed_entries)
                if len(seed_phrase.split()) == seed_length:
                    self.manager.save_seed_phrase(wallet_name, seed_phrase)
                    seed_window.destroy()
                else:
                    messagebox.showerror("Error", f"Seed phrase must contain exactly {seed_length} words.")

            save_button = ttk.Button(seed_window, text="Save Seed Phrase", command=save_seed, bootstyle=SUCCESS)
            save_button.pack(pady=10)

    def clear_default_text(self, entry, seed_entries):
        if entry.get() == str(seed_entries.index(entry) + 1):  # اگر متن پیش‌فرض باشد
            entry.delete(0, tk.END)  # پاک کردن متن
            entry.config(foreground="black")  # تغییر رنگ متن به سیاه

    def retrieve_seed_phrase_dialog(self):
        wallet_name = simpledialog.askstring("Wallet Name", "Enter wallet name:")
        if wallet_name:
            seed_phrase = self.manager.get_seed_phrase(wallet_name)
            if seed_phrase:
                self.show_seed_phrase_details(wallet_name, seed_phrase)
            else:
                messagebox.showerror("Error", "Wallet not found or incorrect master password.")

    def show_seed_phrase_details(self, wallet_name, seed_phrase):
        # ایجاد پنجره‌ی جدید
        seed_window = ttk.Toplevel(self.root)
        seed_window.title(f"Seed Phrase for {wallet_name}")
        seed_window.geometry("600x400")

        # نمایش عنوان
        ttk.Label(seed_window, text=f"Seed Phrase for {wallet_name}:", font=("Helvetica", 14, "bold")).pack(pady=10)

        # تقسیم Seed Phrase به کلمات جداگانه
        seed_words = seed_phrase.split()

        # نمایش کلمات در یک جدول
        seed_frame = ttk.Frame(seed_window)
        seed_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # تنظیم تعداد کلمات در هر ردیف
        words_per_row = 6 if len(seed_words) == 12 else 8  # 12 کلمه در ۲ ردیف، ۲۴ کلمه در ۳ ردیف

        # ایجاد ورودی‌ها برای هر کلمه
        for i, word in enumerate(seed_words):
            if i % words_per_row == 0:
                row_frame = ttk.Frame(seed_frame)
                row_frame.pack()
            entry = ttk.Entry(row_frame, width=10, font=("Helvetica", 12))
            entry.insert(0, word)
            entry.config(state="readonly")  # غیرفعال کردن ویرایش
            entry.pack(side=tk.LEFT, padx=5, pady=5)

            # اضافه کردن رویداد کلیک برای کپی کردن متن
            entry.bind("<Button-1>", lambda event, e=entry: self.copy_entry_text(e))

        # دکمه‌ی کپی کل Seed Phrase
        copy_button = ttk.Button(seed_window, text="Copy Seed Phrase", command=lambda: self.copy_to_clipboard(seed_phrase), bootstyle=INFO)
        copy_button.pack(pady=10)

        # دکمه‌ی بستن پنجره
        ttk.Button(seed_window, text="Close", command=seed_window.destroy, bootstyle=DANGER).pack(pady=20)

    def copy_entry_text(self, entry):
        text = entry.get()  # دریافت متن از Entry
        pyperclip.copy(text)  # کپی متن به کلیپ‌برد
        messagebox.showinfo("Copied", f"'{text}' copied to clipboard!")  # نمایش پیام تأیید

    def delete_seed_phrase_dialog(self):
        wallet_name = simpledialog.askstring("Wallet Name", "Enter wallet name:")
        if wallet_name:
            self.manager.delete_seed_phrase(wallet_name)

    def list_wallets_dialog(self):
        wallets = self.manager.list_wallets()
        self.show_list_window("Wallets", wallets)

    def show_list_window(self, title, items):
        list_window = ttk.Toplevel(self.root)
        list_window.title(title)
        list_window.geometry("400x300")

        # بالا آوردن پنجره جدید
        list_window.lift()
        list_window.focus_force()

        # عنوان پنجره
        ttk.Label(list_window, text=title, font=("Helvetica", 16, "bold")).pack(pady=10)

        # Treeview برای نمایش لیست
        tree = ttk.Treeview(list_window, columns=("Name"), show="headings")
        tree.heading("Name", text="Name")
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        # اضافه کردن آیتم‌ها به Treeview
        for item in items:
            tree.insert("", "end", values=(item,))

        # دکمه بستن پنجره
        close_button = ttk.Button(list_window, text="Close", command=list_window.destroy, bootstyle=DANGER)
        close_button.pack(pady=10)

def generate_keys():
    aes_key = os.urandom(32)
    aes_iv = os.urandom(16)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    fernet_key = Fernet.generate_key()
    return aes_key, aes_iv, private_key, public_key, fernet_key

def multi_layer_encrypt(data, aes_key, aes_iv, public_key, fernet_key):
    # لایه ۱: AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # لایه ۲: RSA
    encrypted_data = public_key.encrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # لایه ۳: Fernet
    fernet = Fernet(fernet_key)
    encrypted_data = fernet.encrypt(encrypted_data)

    return encrypted_data

def multi_layer_decrypt(encrypted_data, aes_key, aes_iv, private_key, fernet_key):
    # لایه ۳: Fernet
    fernet = Fernet(fernet_key)
    decrypted_data = fernet.decrypt(encrypted_data)

    # لایه ۲: RSA
    decrypted_data = private_key.decrypt(
        decrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # لایه ۱: AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv), backend=default_backend())
    decryptor = cipher.decryptor()
    data = decryptor.update(decrypted_data) + decryptor.finalize()

    return data

def derive_key(password, salt):
    """
    یک کلید رمزنگاری از رمز عبور کاربر و نمک تولید می‌کند.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data, key):
    """
    داده‌ها را با استفاده از کلید رمزنگاری می‌کند.
    """
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt_data(encrypted_data, key):
    """
    داده‌های رمزنگاری‌شده را با استفاده از کلید رمزگشایی می‌کند.
    """
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()

def export_backup(file_path, password, backup_data):
    """
    فایل بک‌آپ را رمزنگاری کرده و ذخیره می‌کند.
    """
    try:
        # تولید نمک تصادفی
        salt = os.urandom(16)

        # تولید کلید از رمز عبور کاربر و نمک
        key = derive_key(password, salt)

        # رمزنگاری داده‌های بک‌آپ
        encrypted_data = encrypt_data(json.dumps(backup_data), key)

        # ذخیره‌سازی نمک و داده‌های رمزنگاری‌شده در فایل
        with open(file_path, 'wb') as f:
            f.write(salt + b'::' + encrypted_data)

        messagebox.showinfo("Success", "Backup exported successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to export backup: {e}")

def import_backup(file_path, password):
    """
    فایل بک‌آپ را بازیابی و رمزگشایی می‌کند.
    """
    try:
        # خواندن نمک و داده‌های رمزنگاری‌شده از فایل
        with open(file_path, 'rb') as f:
            data = f.read().split(b'::')
            if len(data) != 2:
                raise ValueError("Invalid backup file format.")
            salt, encrypted_data = data

        # تولید کلید از رمز عبور کاربر و نمک
        key = derive_key(password, salt)

        # رمزگشایی داده‌ها
        decrypted_data = decrypt_data(encrypted_data, key)

        # تبدیل داده‌ها به فرمت JSON
        return json.loads(decrypted_data)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to import backup: {e}")
        return None

def is_strong_password(password):
    """
    بررسی می‌کند که رمز عبور وارد شده شرایط لازم را دارد یا خیر.
    شرایط:
    - حداقل ۱۲ کاراکتر باشد.
    - حداقل یک حرف بزرگ داشته باشد.
    - حداقل یک کاراکتر خاص داشته باشد.
    """
    # بررسی طول رمز عبور
    if len(password) < 12:
        return False, "رمز عبور باید حداقل ۱۲ کاراکتر باشد."
    
    # بررسی وجود حداقل یک حرف بزرگ
    if not re.search(r'[A-Z]', password):
        return False, "رمز عبور باید حداقل یک حرف بزرگ داشته باشد."
    
    # بررسی وجود حداقل یک کاراکتر خاص
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "رمز عبور باید حداقل یک کاراکتر خاص داشته باشد."
    
    # اگر همه شرایط رعایت شده باشد
    return True, "رمز عبور معتبر است."

def set_master_password():
    """
    از کاربر می‌خواهد رمز عبور اصلی را تنظیم کند و شرایط لازم را به او توضیح می‌دهد.
    """
    while True:
        # نمایش شرایط رمز عبور به کاربر
        messagebox.showinfo(
            "شرایط رمز عبور",
            "لطفاً رمز عبور اصلی را تنظیم کنید.\n\n"
            "شرایط رمز عبور:\n"
            "- حداقل ۱۲ کاراکتر باشد.\n"
            "- حداقل یک حرف بزرگ داشته باشد.\n"
            "- حداقل یک کاراکتر خاص داشته باشد (مثل @، !، # و غیره)."
        )
        
        # درخواست رمز عبور از کاربر
        password = simpledialog.askstring("Master Password", "Set a master password:", show='*')
        
        # اگر کاربر رمز عبور را وارد نکرد
        if not password:
            retry = messagebox.askyesno("No Password", "رمز عبور اصلی الزامی است. آیا می‌خواهید دوباره تلاش کنید؟")
            if not retry:
                return None
        
        # بررسی قدرت رمز عبور
        is_strong, message = is_strong_password(password)
        if is_strong:
            return password
        else:
            messagebox.showerror("Weak Password", message)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()

seed_entries = [
    {"wallet_name": "Wallet1", "seed_phrase": "example seed phrase 1"},
    {"wallet_name": "Wallet2", "seed_phrase": "example seed phrase 2"}
]

# استفاده از seed_entries در کد
for entry in seed_entries:
    print(f"Wallet Name: {entry['wallet_name']}, Seed Phrase: {entry['seed_phrase']}")