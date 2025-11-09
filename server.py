#!/usr/bin/env python3
import socket
import struct
import os
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 5001
SERVER_DIR = "server_files"
os.makedirs(SERVER_DIR, exist_ok=True)


def send_with_len(conn, data: bytes):
    conn.sendall(struct.pack("!Q", len(data)))
    if data:
        conn.sendall(data)


def recv_all(conn, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return b""
        data += chunk
    return data


def recv_with_len(conn) -> bytes:
    raw = recv_all(conn, 8)
    if not raw:
        return b""
    (length,) = struct.unpack("!Q", raw)
    if length == 0:
        return b""
    return recv_all(conn, length)


def main():
    key = Fernet.generate_key()
    fernet = Fernet(key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print("[*] Waiting for a client to connect...")
        conn, addr = s.accept()
        print("[+] Client connected:", addr)

        with conn:
            send_with_len(conn, key)

            auth = recv_with_len(conn).decode()
            username, password = auth.split(",")

            if username == "admin" and password == "admin":
                send_with_len(conn, b"AUTH_SUCCESS")
            else:
                send_with_len(conn, b"AUTH_FAIL")
                return

            while True:
                cmd = recv_with_len(conn).decode()

                if cmd == "LIST":
                    files = "\n".join(os.listdir(SERVER_DIR))
                    send_with_len(conn, files.encode())

                elif cmd.startswith("DOWNLOAD"):
                    fname = cmd.split(" ")[1]
                    path = os.path.join(SERVER_DIR, fname)

                    if not os.path.exists(path):
                        send_with_len(conn, b"NOT_FOUND")
                    else:
                        send_with_len(conn, b"FOUND")
                        with open(path, "rb") as f:
                            data = f.read()
                        encrypted = fernet.encrypt(data)
                        send_with_len(conn, encrypted)

                elif cmd.startswith("UPLOAD"):
                    fname = cmd.split(" ")[1]
                    encrypted = recv_with_len(conn)
                    plain = fernet.decrypt(encrypted)

                    with open(os.path.join(SERVER_DIR, fname), "wb") as f:
                        f.write(plain)

                    send_with_len(conn, b"UPLOAD_SUCCESS")

                elif cmd == "EXIT":
                    break


if __name__ == "__main__":
    main()
