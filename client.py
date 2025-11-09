
#!/usr/bin/env python3
import socket
import struct
import os
import hashlib
from cryptography.fernet import Fernet
import getpass

HOST = '127.0.0.1'
PORT = 5001
DOWNLOAD_DIR = "client_files"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def send_with_len(conn, data: bytes):
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

def main():
    print("[*] Connecting to server...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # 1) Receive session key
        key = recv_with_len(s)
        if not key:
            print("[-] Failed to receive encryption key.")
            return
        fernet = Fernet(key)

        # 2) Authenticate
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        send_with_len(s, f"{username},{password}".encode())

        status = recv_with_len(s)
        if status != b"AUTH_SUCCESS":
            print("[-] Authentication failed.")
            return
        print("[+] Authenticated successfully.")

        # 3) Interactive loop
        while True:
            print("\nOptions:")
            print("1 - List files on server")
            print("2 - Download file")
            print("3 - Upload file")
            print("4 - Exit")
            choice = input("Choice: ").strip()

            if choice == "1":
                send_with_len(s, b"LIST")
                listing = recv_with_len(s).decode()
                print("\nFiles on server:")
                print(listing if listing else "(no files)")

            elif choice == "2":
                filename = input("Filename to download: ").strip()
                if not filename:
                    print("[-] No filename given.")
                    continue
                send_with_len(s, f"DOWNLOAD {filename}".encode())
                status = recv_with_len(s)
                if status == b"NOT_FOUND":
                    print("[-] File not found on server.")
                    continue
                elif status == b"FOUND":
                    encrypted = recv_with_len(s)
                    if not encrypted:
                        print("[-] No data received.")
                        continue
                    try:
                        data = fernet.decrypt(encrypted)
                    except Exception as e:
                        print("[-] Decryption failed:", e)
                        continue
                    dest = os.path.join(DOWNLOAD_DIR, filename)
                    with open(dest, "wb") as f:
                        f.write(data)
                    print(f"[+] Downloaded and saved to {dest}")

            elif choice == "3":
                path = input("Path of local file to upload: ").strip()
                if not os.path.exists(path):
                    print("[-] Local file not found.")
                    continue
                filename = os.path.basename(path)
                with open(path, "rb") as f:
                    plain = f.read()
                encrypted = fernet.encrypt(plain)
                send_with_len(s, f"UPLOAD {filename}".encode())
                # send encrypted payload
                send_with_len(s, encrypted)
                resp = recv_with_len(s)
                if resp == b"UPLOAD_SUCCESS":
                    print(f"[+] Uploaded {filename} successfully.")
                else:
                    print("[-] Upload failed or server reported error:", resp)

            elif choice == "4":
                send_with_len(s, b"EXIT")
                print("[*] Exiting.")
                break

            else:
                print("[-] Invalid choice.")

if __name__ == "__main__":
    main()
