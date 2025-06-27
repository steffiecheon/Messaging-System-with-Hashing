#Angeline Babila, Kurt Nivhla Lumibao, Trishia Althea Bonos, Stephanie Tocayon, Block 3-C
#Messaging System with hashing
#Client

import socket
import json
import rsa
import hashlib
import threading
import os

SERVER = '192.168.196.56'
PORT = 12345
KEYS_DIR = 'client_keys'

os.makedirs(KEYS_DIR, exist_ok=True)

def hash_password(pw):
    return hashlib.sha512(pw.encode()).hexdigest()

def hash_message(msg):
    return hashlib.sha512(msg.encode()).hexdigest()

def recv_loop(sock, privkey):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            try:
                msg = json.loads(data.decode())
                encrypted = bytes.fromhex(msg['message'])
                decrypted = rsa.decrypt(encrypted, privkey).decode()
                checksum_valid = hash_message(decrypted) == msg['checksum']
                print(f"\nMessage from {msg['from']}:\n{decrypted}")
                print("Valid" if checksum_valid else "Invalid Checksum")
            except:
                print(data.decode())
        except:
            break

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER, PORT))

    print("1. Register\n2. Login")
    choice = input("Select: ").strip()

    username = input("Username: ").strip()
    password = input("Password: ").strip()

    pubkey_path = f"{KEYS_DIR}/{username}_pub.pem"
    privkey_path = f"{KEYS_DIR}/{username}_priv.pem"

    if choice == "1":
        pubkey, privkey = rsa.newkeys(512)
        with open(pubkey_path, 'wb') as f:
            f.write(pubkey.save_pkcs1())
        with open(privkey_path, 'wb') as f:
            f.write(privkey.save_pkcs1())

        s.send(json.dumps({
            'action': 'register',
            'username': username,
            'password': password,
            'pubkey': pubkey.save_pkcs1().decode()
        }).encode())
        print(s.recv(1024).decode())
        return

    elif choice == "2":
        s.send(json.dumps({
            'action': 'login',
            'username': username,
            'password': password
        }).encode())
        response = s.recv(1024).decode()
        print(response)
        if "successful" not in response:
            return

    with open(privkey_path, 'rb') as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())

    threading.Thread(target=recv_loop, args=(s, privkey), daemon=True).start()

    while True:
        print("\n1. Show Users\n2. Send Message\n3. Quit")
        action = input("Select: ").strip()

        if action == "1":
            s.send(json.dumps({
                'action': 'get_users',
                'username': username
            }).encode())
            users = json.loads(s.recv(2048).decode())
            print("Online Users:", users)

        elif action == "2":
            to_user = input("To: ").strip()
            s.send(json.dumps({'action': 'get_pubkey', 'target': to_user}).encode())
            pubkey_str = s.recv(4096).decode()
            if pubkey_str == "NO_KEY":
                print("No such user.")
                continue
            to_pubkey = rsa.PublicKey.load_pkcs1(pubkey_str.encode())
            msg = input("Message: ")
            encrypted = rsa.encrypt(msg.encode(), to_pubkey).hex()
            checksum = hash_message(msg)

            s.send(json.dumps({
                'action': 'send_message',
                'to': to_user,
                'message': encrypted,
                'checksum': checksum
            }).encode())

        elif action == "3":
            print("Goodbye.")
            break

if __name__ == "__main__":
    main()
