# Server

import socket
import threading
import json
import hashlib
import rsa
import os

HOST = '192.168.196.56'
PORT = 12345
USERS_FILE = 'server_users.json'
KEYS_DIR = 'server_keys'

clients = {}
user_data = {}

os.makedirs(KEYS_DIR, exist_ok=True)

def hash_password(pw):
    return hashlib.sha512(pw.encode()).hexdigest()

def save_user(username, password_hash, public_key):
    user_data[username] = {
        'password': password_hash,
        'pubkey': public_key
    }
    with open(USERS_FILE, 'w') as f:
        json.dump(user_data, f)

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f:
            return json.load(f)
    return {}

def broadcast(recipient, msg):
    if recipient in clients:
        clients[recipient].send(msg.encode())

def handle_client(conn, addr):
    username = None
    while True:
        try:
            data = conn.recv(4096).decode()
            if not data:
                break

            request = json.loads(data)
            action = request.get("action")

            if action == "register":
                username = request["username"]
                pw_hash = hash_password(request["password"])
                pubkey = request["pubkey"]
                if username in user_data:
                    conn.send("User already exists.".encode())
                else:
                    save_user(username, pw_hash, pubkey)
                    conn.send("Registration successful.".encode())

            elif action == "login":
                username = request["username"]
                pw_hash = hash_password(request["password"])
                if username in user_data and user_data[username]['password'] == pw_hash:
                    clients[username] = conn
                    conn.send("Login successful.".encode())
                else:
                    conn.send("Login failed.".encode())

            elif action == "get_users":
                other_users = [u for u in user_data if u != request["username"]]
                conn.send(json.dumps(other_users).encode())

            elif action == "get_pubkey":
                target = request["target"]
                if target in user_data:
                    conn.send(user_data[target]['pubkey'].encode())
                else:
                    conn.send("NO_KEY".encode())

            elif action == "send_message":
                recipient = request["to"]
                if recipient in clients:
                    clients[recipient].send(json.dumps({
                        'from': username,
                        'message': request["message"],
                        'checksum': request["checksum"]
                    }).encode())
                else:
                    conn.send("Recipient offline.".encode())

        except Exception as e:
            print(f"Error: {e}")
            break

    if username in clients:
        del clients[username]
    conn.close()

def start_server():
    global user_data
    user_data = load_users()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[SERVER] Listening on {HOST}:{PORT}...")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()
