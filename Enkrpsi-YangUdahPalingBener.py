import random
import base64
import os
import tkinter as tk
from tkinter import ttk, messagebox, font
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption and Decryption")

        # Set ttk theme
        style = ttk.Style()
        style.theme_use("clam")

        # Add padding to the root window
        root.config(padx=20, pady=20)

        # Set default font after creating the root window
        default_font = font.nametofont("TkDefaultFont")
        default_font.configure(size=12)

        # Labels
        tk.Label(root, text="Encryption:", font=default_font).grid(
            row=0, column=0, sticky="w", pady=(5, 0))
        tk.Label(root, text="Decryption:", font=default_font).grid(
            row=1, column=0, sticky="w", pady=(5, 0))
        tk.Label(root, text="Password:", font=default_font).grid(
            row=2, column=0, sticky="w", pady=(5, 0))
        tk.Label(root, text="Encrypt Result:", font=default_font).grid(
            row=3, column=0, sticky="w", pady=(10, 0))
        tk.Label(root, text="Decrypt Result:", font=default_font).grid(
            row=3, column=2, sticky="w", pady=(10, 0))

        # Text Entry
        self.plaintext_entry = tk.Text(
            root, height=3, width=40, font=default_font)
        self.ciphertext_entry = tk.Text(
            root, height=3, width=40, font=default_font)
        self.password_entry = tk.Entry(
            root, show="*", font=default_font)  # Set show="*"

        self.plaintext_entry.grid(row=0, column=1, padx=10, pady=(5, 10))
        self.ciphertext_entry.grid(row=1, column=1, padx=10, pady=(5, 10))
        self.password_entry.grid(row=2, column=1, padx=10, pady=(5, 10))

        # Result Text
        self.encrypt_result_text = tk.Text(
            root, height=6, width=40, font=default_font)
        self.encrypt_result_text.grid(row=3, column=1, padx=10, pady=(10, 10))

        self.decrypt_result_text = tk.Text(
            root, height=6, width=40, font=default_font)
        self.decrypt_result_text.grid(row=3, column=3, padx=10, pady=(10, 10))

        # Buttons
        encrypt_button = ttk.Button(
            root, text="Encrypt", command=self.on_encrypt_button_click)
        decrypt_button = ttk.Button(
            root, text="Decrypt", command=self.on_decrypt_button_click)
        refresh_button = ttk.Button(
            root, text="Refresh", command=self.on_refresh_button_click)

        # Refresh
        encrypt_button.grid(row=0, column=2, padx=(10, 10), pady=(5, 10))
        decrypt_button.grid(row=1, column=2, padx=(10, 10), pady=(5, 10))
        refresh_button.grid(row=4, column=1, sticky="w", pady=(10, 10))

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt(self, message, public_key):
        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt(self, ciphertext, private_key):
        try:
            decoded_ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
            plaintext = private_key.decrypt(
                decoded_ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext.decode('utf-8')
        except Exception as e:
            messagebox.showerror(
                "Error", "Dekripsi gagal. Pastikan password benar.")
            return None

    def encrypt_with_password(self, text, password):
        # Generate a random initialization vector (IV)
        iv = os.urandom(16)

        # Generate a random AES key
        aes_key = self.derive_key_from_password(password)

        # Encrypt the text using AES in CBC mode
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(text.encode()) + encryptor.finalize()

        # Combine IV, AES key, and ciphertext for later decryption
        encrypted_data = iv + aes_key + ciphertext

        # Encrypt the combined data using RSA public key
        encrypted_result = self.public_key.encrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.b64encode(encrypted_result).decode('utf-8')

    def decrypt_with_password(self, encrypted_text, password):
        try:
            # Decrypt the combined data using RSA private key
            decoded_ciphertext = base64.b64decode(
                encrypted_text.encode('utf-8'))
            decrypted_data = self.private_key.decrypt(
                decoded_ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Extract IV, AES key, and ciphertext from decrypted data
            iv = decrypted_data[:16]
            aes_key = decrypted_data[16:48]
            ciphertext = decrypted_data[48:]

            # Check if the entered password is correct
            if self.check_password_correctness(password, decrypted_data):
                # Decrypt the ciphertext using AES
                cipher = Cipher(algorithms.AES(aes_key), modes.CFB(
                    iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_text = decryptor.update(
                    ciphertext) + decryptor.finalize()

                return decrypted_text.decode('utf-8')
            else:
                # Show an error message if password is incorrect
                messagebox.showerror(
                    "Error", "Dekripsi gagal. Pastikan password benar.")
                return None

        except Exception as e:
            # Show an error message if decryption fails
            messagebox.showerror(
                "Error", "Dekripsi gagal. Pastikan password benar.")
            return None

    def derive_key_from_password(self, password):
        # Simulate the same process used during encryption to derive the key
        random.seed(password)
        return random.randbytes(32)

    def check_password_correctness(self, entered_password, decrypted_data):
        # Simulate the same process used during encryption to derive the key
        expected_aes_key = self.derive_key_from_password(entered_password)

        # Check if the derived key matches the key stored in the decrypted data
        return expected_aes_key == decrypted_data[16:48]

    def show_notification(self, message):
        messagebox.showinfo("Notification", message)

    def on_encrypt_button_click(self):
        plaintext = self.plaintext_entry.get("1.0", tk.END).strip()
        password = self.password_entry.get()
        self.private_key, self.public_key = self.generate_key_pair()
        encrypted_text = self.encrypt_with_password(plaintext, password)
        self.encrypt_result_text.delete("1.0", tk.END)
        self.encrypt_result_text.insert(tk.END, f"{encrypted_text}")
        self.show_notification("Encrypt berhasil!")

    def on_decrypt_button_click(self):
        encrypted_text = self.ciphertext_entry.get("1.0", tk.END).strip()
        password = self.password_entry.get()
        decrypted_text = self.decrypt_with_password(encrypted_text, password)
        if decrypted_text is not None:
            self.decrypt_result_text.delete("1.0", tk.END)
            self.decrypt_result_text.insert(tk.END, f"{decrypted_text}")
            self.show_notification("Decrypt berhasil!")

    def on_refresh_button_click(self):
        # Fungsi untuk membersihkan teks di semua kotak teks
        self.plaintext_entry.delete("1.0", tk.END)
        self.ciphertext_entry.delete("1.0", tk.END)
        self.password_entry.delete(0, tk.END)
        self.encrypt_result_text.delete("1.0", tk.END)
        self.decrypt_result_text.delete("1.0", tk.END)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    app.run()
