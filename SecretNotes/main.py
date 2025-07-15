import base64
import json
from tkinter import *
from tkinter import messagebox

# -------------------- Encryption Functions --------------------
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    try:
        enc = base64.urlsafe_b64decode(enc).decode()
    except Exception:
        return "[WRONG PASSWORD]"
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

# -------------------- File Handling --------------------
def save_note(title, encrypted_message):
    try:
        with open("mysecret.json", "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        data = {}

    data[title] = encrypted_message

    with open("mysecret.json", "w") as file:
        json.dump(data, file, indent=4)

def load_note(title):
    try:
        with open("mysecret.json", "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        return None

    return data.get(title)

# -------------------- Button Functions --------------------
def save_and_encrypt_notes():
    title = title_entry.get()
    message = input_text.get("1.0", END).strip()
    master_secret = master_secret_entry.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showerror(title="Error", message="Please fill in all fields.")
    else:
        encrypted = encode(master_secret, message)
        save_note(title, encrypted)

        title_entry.delete(0, END)
        input_text.delete("1.0", END)
        master_secret_entry.delete(0, END)

        messagebox.showinfo(title="Success", message="Note encrypted and saved!")

def decrypt_notes():
    title = title_entry.get()
    master_secret = master_secret_entry.get()

    if len(title) == 0 or len(master_secret) == 0:
        messagebox.showerror(title="Error", message="Please enter title and master key.")
    else:
        encrypted_message = load_note(title)
        if encrypted_message is None:
            messagebox.showerror(title="Error", message="No note found with this title.")
        else:
            decrypted = decode(master_secret, encrypted_message)
            input_text.delete("1.0", END)
            input_text.insert("1.0", decrypted)

# -------------------- UI --------------------
window = Tk()
window.title("🔐 Secret Notes")
window.geometry("500x600")
window.config(padx=20, pady=20)

# Image (optional)
try:
    photo = PhotoImage(file="topsecret.png")
    photo = photo.subsample(8, 8)
    canvas = Canvas(window, width=200, height=200)
    canvas.create_image(100, 100, image=photo, anchor=CENTER)
    canvas.pack()
except:
    pass  # Do nothing if image not found

# Title Entry
Label(window, text="Note Title", font=("Arial", 14)).pack()
title_entry = Entry(window, width=40)
title_entry.pack(pady=5)

# Note Text
Label(window, text="Note Content", font=("Arial", 14)).pack()
input_text = Text(window, width=40, height=10)
input_text.pack(pady=5)

# Master Key
Label(window, text="Master Key", font=("Arial", 14)).pack()
master_secret_entry = Entry(window, width=40, show="*")
master_secret_entry.pack(pady=5)

# Buttons
Button(text="💾 Save & Encrypt", command=save_and_encrypt_notes).pack(pady=10)
Button(text="🔓 Decrypt", command=decrypt_notes).pack()

window.mainloop()
