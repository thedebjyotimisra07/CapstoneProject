#!/usr/bin/env python3
import socket
import os
import struct
import hashlib
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 5001
FILES_DIR = "server_files"
os.makedirs(FILES_DIR, exist_ok=True)

# Simple user DB: username -> sha256(password)
USERS = {
    "admin": hashlib.sha256("password".encode()).hexdigest()
}

# Helpers: length-prefixed send/recv
def send_with_len(conn, data: bytes):
    """Send 8-byte length prefix + data"""
    conn.sendall(struct.pack("!Q", len(data)))
    if data:
        conn.sendall(data)

def recv_all(conn, n: int) -> bytes:
    data = b""
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return b""
        data += packet
    return data

def recv_with_len(conn) -> bytes:
    raw_len = recv_all(conn, 8)
    if not raw_len:
        return b""
    (length,) = struct.unpack("!Q", raw_len)
    if length == 0:
        return b""
    return recv_all(conn, length)

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")

    # 1) Create a fresh symmetric key for this session and send to client
    key = Fernet.generate_key()
    fernet = Fernet(key)
    send_with_len(conn, key)

    # 2) Authentication: expect "username,password" as plain text from client
    cred_bytes = recv_with_len(conn)
    if not cred_bytes:
        print("[-] No credentials received; closing.")
        conn.close()
        return
    try:
        username, password = cred_bytes.decode().split(",", 1)
    except Exception:
        conn.close()
        return

    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    if username in USERS and USERS[username] == pw_hash:
        send_with_len(conn, b"AUTH_SUCCESS")
        print(f"[+] Authenticated user: {username}")
    else:
        send_with_len(conn, b"AUTH_FAIL")
        print(f"[-] Authentication failed for: {username}")
        conn.close()
        return

    # 3) Handle commands
    try:
        while True:
            cmd_bytes = recv_with_len(conn)
            if not cmd_bytes:
                print("[*] Client disconnected.")
                break
            cmd = cmd_bytes.decode()

            if cmd == "LIST":
                files = os.listdir(FILES_DIR)
                listing = "\n".join(files) if files else ""
                send_with_len(conn, listing.encode())

            elif cmd.startswith("DOWNLOAD "):
                _, filename = cmd.split(" ", 1)
                filepath = os.path.join(FILES_DIR, filename)
                if not os.path.exists(filepath):
                    send_with_len(conn, b"NOT_FOUND")
                    print(f"[-] Requested file not found: {filename}")
                    continue
                # read file, encrypt, send length-prefixed encrypted bytes
                with open(filepath, "rb") as f:
                    plain = f.read()
                encrypted = fernet.encrypt(plain)
                send_with_len(conn, b"FOUND")
                send_with_len(conn, encrypted)
                print(f"[*] Sent (encrypted) file: {filename}")

            elif cmd.startswith("UPLOAD "):
                _, filename = cmd.split(" ", 1)
                # Server signals READY implicitly by expecting next recv_with_len to be data
                encrypted_data = recv_with_len(conn)
                if not encrypted_data:
                    send_with_len(conn, b"UPLOAD_FAIL")
                    print(f"[-] No data for upload {filename}")
                    continue
                try:
                    data = fernet.decrypt(encrypted_data)
                except Exception as e:
                    send_with_len(conn, b"DECRYPT_FAIL")
                    print("[-] Decryption failed:", e)
                    continue
                dest = os.path.join(FILES_DIR, filename)
                with open(dest, "wb") as f:
                    f.write(data)
                send_with_len(conn, b"UPLOAD_SUCCESS")
                print(f"[+] Received and saved file: {filename}")

            elif cmd == "EXIT":
                print("[*] Client requested exit.")
                break

            else:
                send_with_len(conn, b"UNKNOWN_COMMAND")
    finally:
        conn.close()
        print(f"[-] Connection closed: {addr}")

if __name__ == "__main__":
    print("[*] Server starting...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[*] Listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            # For simplicity this server is single-threaded and handles one connection at a time.
            # If you want concurrent clients, spawn a thread: threading.Thread(target=handle_client, args=(conn, addr)).start()
            handle_client(conn, addr)
