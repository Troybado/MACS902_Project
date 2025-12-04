import ssl  # Importing the SSL module to create a TLS-secured context for encrypted server-client communication
import socket  # Importing the socket module to work with network sockets (TCP server)
import sqlite3  # Importing sqlite3 to store user records locally in a lightweight relational database file
import bcrypt  # Importing bcrypt for secure password hashing and verification, resistant to brute-force attacks
import threading  # Importing threading to handle multiple client connections concurrently in separate threads

DB = "classical_users.db"  # Defining the SQLite database filename to store user credentials
HOST = "0.0.0.0"  # Binding to all network interfaces so clients can connect from any reachable address
PORT = 4443  # Choosing port 4443 for the TLS server as it is a common alternative to 443 for demos

def init_db():  # Defining a function to initialise the database schema
    con = sqlite3.connect(DB)  # Opening a connection to the SQLite database file
    cur = con.cursor()  # Obtaining a cursor to execute SQL statements
    # Executing a SQL command to create the users table if it does not exist
    cur.execute(""" 
        CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY,  
            pw_hash  BLOB NOT NULL  
        )
    """)
    con.commit()  # Committing the transaction to ensure schema changes are saved
    con.close()  # Closing the database connection to release resources

def add_user(username, password):  # Defining a helper function to insert or update a user record
    con = sqlite3.connect(DB)  # Opening a new database connection
    cur = con.cursor()  # Geting a cursor for SQL operations
    h = bcrypt.hashpw(password.encode(), bcrypt.gensalt())  # Hashing the plaintext password with a random salt using bcrypt
    cur.execute("INSERT OR REPLACE INTO users(username,pw_hash) VALUES(?,?)", (username, h))  # Inserting user and hashed password
    con.commit()  # Committing the change so it stores
    con.close()  # Closing the connection after this operation

def check_user(username, password):  # Defiinge a function to verify credentials on login
    con = sqlite3.connect(DB)  # Opening the database connection for read
    cur = con.cursor()  # Creating a cursor to execute queries
    cur.execute("SELECT pw_hash FROM users WHERE username=?", (username,))  # Retrieving the stored hash for the given username
    row = cur.fetchone()  # Fetching one row (None if user not found)
    con.close()  # Closing the database after reading to avoid leaks
    if not row:  # If no record found, credentials are invalid
        return False  # Returns False immediately
    return bcrypt.checkpw(password.encode(), row[0])  # Using bcrypt to verify provided password against stored hash

def handle(conn):  # Defining a per-client handler function to process login interaction over TLS
    try:  # Using try to ensure clean closure even on errors
        conn.sendall(b"Username: ")  # Prompting the client for a username over the TLS stream
        u = conn.recv(4096).strip().decode()  # Reading up to 4KB, trim whitespace, decode bytes to string as username
        conn.sendall(b"Password: ")  # Prompting the client for a password
        p = conn.recv(4096).strip().decode()  # Reading, stripping, and decoding the password from the TLS stream
        if check_user(u, p):  # Verifying credentials using the database and bcrypt
            conn.sendall(b"[OK] Logged in (classical)\n")  # Sending success message if credentials are valid
        else:  # If verification fails
            conn.sendall(b"[NO] Invalid creds\n")  # Sending failure message to the client
    except Exception as e:  # Catching any runtime exceptions (e.g., network errors)
        try:  # Attempting to notify the client of an error
            conn.sendall(b"[ERR]\n")  # Sending a generic error indicator
        except:  # If sending fails, ignore to avoid cascading errors
            pass  # Doing nothing on send failure
    finally:  # Always executes cleanup
        conn.close()  # Closing the TLS-wrapped connection to free resources

def main():  # Defining the main entry point function
    init_db()  # Ensuring the database and users table are initialised before accepting clients
    add_user("alice", "Password123!")  # Creating a demo user for testing; in production, will handle registration securely
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # Creating a TLS server context to enable encrypted connections
    ctx.load_cert_chain("rsa_server.crt", "rsa_server.key")  # Loading RSA certificate and private key for server authentication
    s = socket.socket()  # Creating a TCP socket for listening to incoming client connections
    s.bind((HOST, PORT))  # Binding the socket to the specified address and port
    s.listen(5)  # Start listening with a backlog of 5 pending connections
    print(f"[classical] listening on {PORT}")  # Logging to console that the classical TLS server is ready
    while True:  # Looping indefinitely to accept and handle multiple clients
        c, addr = s.accept()  # Accepting a new TCP connection and getting the client address tuple
        tls = ctx.wrap_socket(c, server_side=True)  # Wraping the raw socket in TLS to encrypt the session
        threading.Thread(target=handle, args=(tls,), daemon=True).start()  # Spawning a daemon thread to handle this client concurrently

if __name__ == "__main__":  # Standard Python pattern to run main only when executed directly
    main()  # Calling the main function to start the server
