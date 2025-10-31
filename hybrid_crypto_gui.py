import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils
import base64, os

# ---------- Key Generation ----------
sender_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
sender_public_key = sender_private_key.public_key()

receiver_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
receiver_public_key = receiver_private_key.public_key()

# ---------- Encryption Function ----------
def encrypt_message(message):
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    # AES Encryption
    padder = sympadding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Encrypt AES key with Receiver's Public Key
    enc_aes_key = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Create SHA256 hash and sign with Sender's Private Key
    message_hash = hashes.Hash(hashes.SHA256())
    message_hash.update(message.encode())
    digest = message_hash.finalize()

    signature = sender_private_key.sign(
        digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        utils.Prehashed(hashes.SHA256())
    )

    # Encode everything in Base64 for transmission
    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(enc_aes_key).decode(),
        base64.b64encode(iv).decode(),
        base64.b64encode(signature).decode()
    )

# ---------- Decryption + Verification Function ----------
def decrypt_message(encrypted_message, enc_aes_key, iv, signature):
    try:
        ciphertext = base64.b64decode(encrypted_message)
        enc_aes_key = base64.b64decode(enc_aes_key)
        iv = base64.b64decode(iv)
        signature = base64.b64decode(signature)

        # Decrypt AES key using Receiver’s Private Key
        aes_key = receiver_private_key.decrypt(
            enc_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # AES Decryption
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sympadding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        plaintext = plaintext.decode()

        # Verify Signature (Authenticity + Integrity)
        message_hash = hashes.Hash(hashes.SHA256())
        message_hash.update(plaintext.encode())
        digest = message_hash.finalize()

        sender_public_key.verify(
            signature,
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            utils.Prehashed(hashes.SHA256())
        )

        return plaintext, True  # Signature valid ✅

    except Exception as e:
        return str(e), False  # Verification failed ❌

# ---------- GUI ----------
root = tk.Tk()
root.title("Secure Communication Channel (AES + RSA + Signature)")
root.geometry("850x600")
root.config(bg="#1e1e1e")

label_style = {"bg": "#1e1e1e", "fg": "#00ffcc", "font": ("Consolas", 12, "bold")}
text_style = {"bg": "#2d2d2d", "fg": "#ffffff", "insertbackground": "white", "font": ("Consolas", 11)}

tk.Label(root, text="Enter Message to Send:", **label_style).pack(pady=5)
text_input = scrolledtext.ScrolledText(root, height=5, width=90, **text_style)
text_input.pack(pady=5)

tk.Label(root, text="Encrypted Data:", **label_style).pack(pady=5)
text_output = scrolledtext.ScrolledText(root, height=7, width=90, **text_style)
text_output.pack(pady=5)

tk.Label(root, text="Decrypted Message:", **label_style).pack(pady=5)
text_decrypted = scrolledtext.ScrolledText(root, height=4, width=90, **text_style)
text_decrypted.pack(pady=5)

status_label = tk.Label(root, text="", bg="#1e1e1e", fg="#aaaaaa", font=("Consolas", 10, "italic"))
status_label.pack(pady=10)

def encrypt_action():
    msg = text_input.get("1.0", tk.END).strip()
    if not msg:
        messagebox.showwarning("Warning", "Enter a message to encrypt!")
        return
    ciphertext, enc_key, iv, sig = encrypt_message(msg)
    data = f"Ciphertext:\n{ciphertext}\n\nEncrypted AES Key:\n{enc_key}\n\nIV:\n{iv}\n\nSignature:\n{sig}"
    text_output.delete("1.0", tk.END)
    text_output.insert(tk.END, data)
    status_label.config(text="✅ Message encrypted and signed successfully!", fg="#00ffcc")

def decrypt_action():
    try:
        content = text_output.get("1.0", tk.END).strip().split("\n\n")
        ciphertext = content[0].split("\n")[1]
        enc_key = content[1].split("\n")[1]
        iv = content[2].split("\n")[1]
        sig = content[3].split("\n")[1]
        plaintext, verified = decrypt_message(ciphertext, enc_key, iv, sig)
        text_decrypted.delete("1.0", tk.END)
        text_decrypted.insert(tk.END, plaintext)
        if verified:
            messagebox.showinfo("Verified", "✅ Decryption successful and signature verified!")
            status_label.config(text="✅ Integrity and authenticity verified!", fg="#00ffcc")
        else:
            messagebox.showerror("Error", "❌ Signature verification failed!")
            status_label.config(text="❌ Verification failed!", fg="#ff3333")
    except Exception as e:
        messagebox.showerror("Error", str(e))

tk.Button(root, text="🔒 Encrypt & Sign", command=encrypt_action, bg="#00b894", fg="white", font=("Consolas", 11, "bold"), width=18).pack(pady=5)
tk.Button(root, text="🔓 Decrypt & Verify", command=decrypt_action, bg="#0984e3", fg="white", font=("Consolas", 11, "bold"), width=18).pack(pady=5)

tk.Label(root, text="Developed by Jitesh Singh (ID: 1000019300)", bg="#1e1e1e", fg="#888888", font=("Consolas", 10, "italic")).pack(side="bottom", pady=10)

root.mainloop()
