import ssl  # TLS context for encrypted server-client communication
import socket  # TCP sockets
import sqlite3  # lightweight local DB
import bcrypt  # secure password hashing/verification
import threading  # handle multiple clients concurrently

DB = "classical_users.db"
HOST = "0.0.0.0"
PORT = 4443


def init_db():
    """Initialise the SQLite schema."""
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY,
            pw_hash BLOB NOT NULL
        )
        """
    )
    con.commit()
    con.close()


def add_user(username, password):
    """Insert or replace a user with bcrypt-hashed password."""
    con = sqlite3.connect(DB)
    cur = con.cursor()
    h = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cur.execute(
        "INSERT OR REPLACE INTO users(username,pw_hash) VALUES(?,?)",
        (username, h),
    )
    con.commit()
    con.close()


def check_user(username, password):
    """Verify credentials."""
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("SELECT pw_hash FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    con.close()
    if not row:
        return False
    return bcrypt.checkpw(password.encode(), row[0])


def handle(conn):
    """Per-client TLS login handler."""
    try:
        conn.sendall(b"Username: ")
        u = conn.recv(4096).strip().decode()

        conn.sendall(b"Password: ")
        p = conn.recv(4096).strip().decode()

        if check_user(u, p):
            conn.sendall(b"[OK] Logged in (classical)\n")
        else:
            conn.sendall(b"[NO] Invalid creds\n")

    except Exception:
        try:
            conn.sendall(b"[ERR]\n")
        except Exception:
            pass
    finally:
        conn.close()


def main():
    init_db()
    add_user("alice", "Password123!")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("rsa_server.crt", "rsa_server.key")

    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[classical] listening on {PORT}")

    while True:
        c, addr = s.accept()
        tls = ctx.wrap_socket(c, server_side=True)
        threading.Thread(target=handle, args=(tls,), daemon=True).start()


if __name__ == "__main__":
    main()
