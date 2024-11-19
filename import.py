import os
import tkinter as tk
from tkinter import font, messagebox, filedialog, Tk
import webbrowser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# RSA Functions
def key_generation():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    os.makedirs('keypairs', exist_ok=True)

    # Serialize and write the public key
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('keypairs/publicKey.pem', 'wb') as f:
        f.write(pem)

    # Serialize and write the private key
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('keypairs/privateKey.pem', 'wb') as f:
        f.write(pem)

    messagebox.showinfo("Success", "RSA Key pair has been created")


def open_keys():
    with open('keypairs/publicKey.pem', 'rb') as f:
        pem = f.read()
        public_key = serialization.load_pem_public_key(pem, backend=default_backend())

    with open('keypairs/privateKey.pem', 'rb') as f:
        pem = f.read()
        private_key = serialization.load_pem_private_key(pem, password=None, backend=default_backend())

    return public_key, private_key



def encryption(msg, key):
    ciphertext = key.encrypt(
        msg.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decryption(ciphertext, key):
    try:
        plaintext = key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')
    except:
        return False
# Encrypts plaintext input to ciphertext using RSA
def message_encryption_rsa():
    message = message_entry.get()
    publicKey, privateKey = open_keys()
    ciphertext = encryption(message, publicKey)
    entered_ciphertext.delete(0, tk.END)
    entered_ciphertext.insert(tk.END, str(ciphertext))

# Diffie-Hellman Functions
def prime_checker(p):
    # Checks If the number entered is a Prime Number or not
    if p < 1:
        return -1
    elif p > 1:
        if p == 2:
            return 1
        for i in range(2, p):
            if p % i == 0:
                return -1
            return 1

def primitive_check(g, p, L):
    # Checks If The Entered Number Is A Primitive Root Or Not
    for i in range(1, p):
        L.append(pow(g, i) % p)
    for i in range(1, p):
        if L.count(i) > 1:
            L.clear()
            return -1
    return 1

# GUI
window = tk.Tk()
window.title("RSA and Diffie-Hellman Encryption")
window.geometry("500x600")

content_frame = tk.Frame(window, bg='#1C3012', bd=5000)
content_frame.place(relx=0.5, rely=0.5, anchor='center')

label = tk.Label(content_frame, text="Please choose an option:", font=("Segoe Script", 14), bg='#9DE0AD')
label.pack(pady=10)

generate_rsa_btn = tk.Button(content_frame, text="Generate RSA Key Pair", width=25, command=key_generation, bg='#AFE1AF')
generate_rsa_btn.pack()

encrypt_rsa_btn = tk.Button(content_frame, text="Encrypt Message (RSA)", width=25, command=message_encryption_rsa, bg='#AFE1AF')
encrypt_rsa_btn.pack(pady=10)


generate_diffie_hellman_btn = tk.Button(content_frame, text="Generate Diffie-Hellman Keys", width=25, command=diffie_hellman_key_exchange, bg='#AFE1AF')
generate_diffie_hellman_btn.pack(pady=10)

exit_btn = tk.Button(content_frame, text="Quit", width=20, command=exit_program, bg='#AFE1AF')
exit_btn.pack()

message_label = tk.Label(content_frame, text="Enter Message:", font=("Segoe Script", 12), bg='#9DE0AD')
message_label.pack(pady=10)

message_entry = tk.Entry(content_frame, width=50)
message_entry.pack()

ciphertext_label = tk.Label(content_frame, text="Enter Ciphertext:", font=("Segoe Script", 12), bg='#9DE0AD')
ciphertext_label.pack(pady=10)

entered_ciphertext = tk.Entry(content_frame, width=50)
entered_ciphertext.pack()

plaintext_label = tk.Label(content_frame, text="Decrypted Plaintext:", font=("Segoe Script", 12), bg='#9DE0AD')
plaintext_label.pack(pady=10)

plaintext_entry = tk.Entry(content_frame, width=50)
plaintext_entry.pack()

email_label = tk.Label(content_frame, text="Enter Recipient's Email:", font=("Segoe Script", 12), bg='#9DE0AD')
email_label.pack(pady=10)

email_entry = tk.Entry(content_frame, width=50)
email_entry.pack()

send_email_btn = tk.Button(content_frame, text="Send", font=("Calibri", 12, 'bold'), width=20, command=send_email, bg='#AFE1AF')
send_email_btn.pack(pady=10)

window.mainloop()

# Diffie-Hellman Key Exchange Function
def diffie_hellman_key_exchange():
    l = []
    while 1:
        P = int(input("Enter P: "))
        if prime_checker(P) == -1:
            print("Number Is Not Prime, Please Enter Again!")
            continue
        break

    while 1:
        G = int(input(f"Enter The Primitive Root Of {P}: "))
        if primitive_check(G, P, l) == -1:
            print(f"Number Is Not A Primitive Root Of {P}, Please Try Again!")
            continue
        break

    # Private Keys
    x1, x2 = int(input("Enter The Private Key Of User 1: ")), int(input("Enter The Private Key Of User 2: "))
    while 1:
        if x1 >= P or x2 >= P:
            print(f"Private Key Of Both The Users Should Be Less Than {P}!")
            continue
        break

    # Calculate Public Keys
    y1, y2 = pow(G, x1) % P, pow(G, x2) % P

    # Generate Secret Keys
    k1, k2 = pow(y2, x1) % P, pow(y1, x2) % P

    print(f"\nSecret Key For User 1 Is {k1}\nSecret Key For User 2 Is {k2}\n")

    if k1 == k2:
        print("Keys Have Been Exchanged Successfully")
    else:
        print("Keys Have Not Been Exchanged Successfully")

# Continue with your GUI code
generate_diffie_hellman_btn = tk.Button(content_frame, text="Generate Diffie-Hellman Keys", width=25, command=diffie_hellman_key_exchange, bg='#AFE1AF')
generate_diffie_hellman_btn.pack(pady=10)

# Continue with the rest of your GUI code and the main loop
window.mainloop()