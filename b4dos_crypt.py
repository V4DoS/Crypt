# b4dos_crypt.py
# Полная версия с красивым интерфейсом и работающей кнопкой "Выход"

import os
import sys
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import secrets

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

SUFFIX = ".B4DoS"


def load_public_key(key_path: Path):
    try:
        return serialization.load_pem_public_key(
            key_path.read_bytes(),
            backend=default_backend()
        )
    except Exception as e:
        raise ValueError(f"Не удалось загрузить публичный ключ\n{str(e)}")


def load_private_key(key_path: Path, password: bytes | None = None):
    try:
        return serialization.load_pem_private_key(
            key_path.read_bytes(),
            password=password,
            backend=default_backend()
        )
    except Exception as e:
        raise ValueError(f"Не удалось загрузить приватный ключ\n{str(e)}")


def encrypt_file(src: Path, pub_key, suffix: str = SUFFIX) -> bool:
    if src.suffix == suffix or src.name.endswith(suffix):
        return False

    dst = src.with_name(src.name + suffix)
    if dst.exists():
        print(f"Пропуск — уже существует: {dst.name}")
        return False

    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)

    enc_aes_key = pub_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    try:
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            fout.write(len(enc_aes_key).to_bytes(4, "big"))
            fout.write(enc_aes_key)
            fout.write(iv)

            while chunk := fin.read(256 * 1024):
                fout.write(encryptor.update(chunk))

            fout.write(encryptor.finalize())
            fout.write(encryptor.tag)

        os.remove(src)
        print(f"[ШИФР + УДАЛЁН] {src.name} → {dst.name}")
        return True

    except Exception as e:
        if dst.exists():
            dst.unlink(missing_ok=True)
        print(f"[ОШИБКА шифрования] {src.name}: {e}")
        return False


def decrypt_file(src: Path, priv_key, suffix: str = SUFFIX) -> bool:
    if not src.name.endswith(suffix):
        return False

    dst = src.with_name(src.name.removesuffix(suffix))
    if dst.exists():
        print(f"Пропуск — оригинал уже существует: {dst.name}")
        return False

    try:
        with open(src, "rb") as f:
            key_len = int.from_bytes(f.read(4), "big")
            enc_aes_key = f.read(key_len)
            iv = f.read(16)
            remaining = f.read()

            if len(remaining) < 16:
                raise ValueError("Файл повреждён — отсутствует тег")

            ciphertext = remaining[:-16]
            tag = remaining[-16:]

        aes_key = priv_key.decrypt(
            enc_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        with open(dst, "wb") as fout:
            fout.write(decryptor.update(ciphertext))
            fout.write(decryptor.finalize_with_tag(tag))

        os.remove(src)
        print(f"[РАСШИФР + УДАЛЁН] {src.name} → {dst.name}")
        return True

    except Exception as e:
        if dst.exists():
            dst.unlink(missing_ok=True)
        print(f"[ОШИБКА расшифровки] {src.name}: {e}")
        return False


def process_directory(path: Path, mode: str, key_obj):
    count_ok = 0
    count_err = 0

    for root, _, files in os.walk(path):
        for fname in files:
            fp = Path(root) / fname

            if fp.name in {"rsa_private_4096.pem", "rsa_public_4096.pem"}:
                continue

            try:
                if mode == "encrypt":
                    if encrypt_file(fp, key_obj):
                        count_ok += 1
                elif mode == "decrypt":
                    if decrypt_file(fp, key_obj):
                        count_ok += 1
            except Exception as e:
                print(f"[ОШИБКА] {fp}: {e}")
                count_err += 1

    return count_ok, count_err


# ─────────────────────────────────────────────────────────────
#                  Красивое главное окно
# ─────────────────────────────────────────────────────────────

class CryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("B4DoS Crypt Tool")
        self.root.geometry("500x340")
        self.root.resizable(False, False)
        self.root.configure(bg="#f5f5f5")

        # Стили для ttk кнопок
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Segoe UI", 13), padding=10)
        style.map("TButton", background=[("active", "#e0e0e0")])

        # Заголовок
        tk.Label(
            root,
            text="B4DoS Crypt Tool",
            font=("Segoe UI", 18, "bold"),
            bg="#f5f5f5",
            fg="#1a237e",
            pady=20
        ).pack()

        tk.Label(
            root,
            text="Выберите действие:",
            font=("Segoe UI", 12),
            bg="#f5f5f5",
            fg="#424242",
            pady=5
        ).pack()

        # Кнопка шифрования
        ttk.Button(
            root,
            text="Зашифровать папку",
            command=self.encrypt_mode,
            style="TButton",
            width=28
        ).pack(pady=10)

        # Кнопка расшифровки
        ttk.Button(
            root,
            text="Расшифровать папку",
            command=self.decrypt_mode,
            style="TButton",
            width=28
        ).pack(pady=10)

        # Кнопка выхода — обычный tk.Button, чтобы точно был текст
        tk.Button(
            root,
            text="Выход",
            command=root.quit,
            font=("Segoe UI", 11),
            bg="#ef5350",
            fg="white",
            activebackground="#d32f2f",
            activeforeground="white",
            width=15,
            height=2,
            relief="raised",
            bd=1,
            cursor="hand2"
        ).pack(pady=35)

    def encrypt_mode(self):
        self.root.withdraw()
        self.process("encrypt")

    def decrypt_mode(self):
        self.root.withdraw()
        self.process("decrypt")

    def process(self, mode):
        is_encrypt = mode == "encrypt"
        mode_text = "шифрования" if is_encrypt else "расшифровки"
        delete_text = "оригинальные файлы будут удалены после успешного шифрования" if is_encrypt else "файлы .B4DoS будут удалены после успешной расшифровки"

        folder = filedialog.askdirectory(
            title=f"Выберите папку для {mode_text}",
            initialdir=os.path.expanduser("~")
        )
        if not folder:
            self.root.deiconify()
            return

        target = Path(folder).resolve()

        if is_encrypt:
            key_path_str = filedialog.askopenfilename(
                title="Выберите публичный ключ (rsa_public_4096.pem)",
                filetypes=[("PEM файлы", "*.pem"), ("Все файлы", "*.*")],
                initialdir=os.path.expanduser("~")
            )
            if not key_path_str:
                self.root.deiconify()
                return

            try:
                key_obj = load_public_key(Path(key_path_str))
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось загрузить публичный ключ:\n{e}")
                self.root.deiconify()
                return
        else:
            key_path_str = filedialog.askopenfilename(
                title="Выберите приватный ключ (rsa_private_4096.pem)",
                filetypes=[("PEM файлы", "*.pem"), ("Все файлы", "*.*")],
                initialdir=os.path.expanduser("~")
            )
            if not key_path_str:
                self.root.deiconify()
                return

            key_path = Path(key_path_str)
            password = None

            try:
                key_obj = load_private_key(key_path, None)
            except Exception as e:
                err = str(e).lower()
                if "password" in err or "bad decrypt" in err or "decrypt" in err:
                    pwd = simpledialog.askstring(
                        "Пароль ключа",
                        "Введите пароль для приватного ключа\n(ввод скрыт)",
                        show="*"
                    )
                    if pwd is None:
                        self.root.deiconify()
                        return
                    password = pwd.encode()
                else:
                    messagebox.showerror("Ошибка", f"Не удалось загрузить ключ:\n{e}")
                    self.root.deiconify()
                    return

            if password is not None:
                try:
                    key_obj = load_private_key(key_path, password)
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Неверный пароль или повреждённый ключ:\n{e}")
                    self.root.deiconify()
                    return

        confirm = messagebox.askyesno(
            "Подтверждение операции",
            f"Папка: {target}\n\n"
            f"Режим: {mode_text}\n"
            f"{delete_text}\n\n"
            f"Запустить процесс?",
            icon="warning"
        )

        if not confirm:
            self.root.deiconify()
            return

        ok, err = process_directory(target, mode, key_obj)

        messagebox.showinfo(
            "Результат",
            f"Обработка завершена\n\n"
            f"Успешно: {ok} файлов\n"
            f"С ошибками: {err}"
        )

        self.root.deiconify()


if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = CryptApp(root)
        root.mainloop()
    except Exception as e:
        tk.Tk().withdraw()
        messagebox.showerror("Критическая ошибка", str(e))
        sys.exit(1)