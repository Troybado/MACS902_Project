# Classical TLS vs Post-Quantum Login

This repository contains code snippets extracted from the project report.  
It demonstrates two authentication approaches:

1. **Classical TLS + Password Login** (server-side bcrypt + SQLite)
2. **Post-Quantum Cryptography (PQC) Challenge-Response Login** using **Dilithium2 signatures**

---

## Repository Structure

```
.
├── classical_server.py   # TLS socket server + bcrypt/SQLite user auth
├── pqc_login.py          # Flask REST server issuing PQC challenges
├── pqc_client.py         # Client that registers key, signs challenge, logs in
└── README.md
```

---

## 1) Classical TLS Password Authentication

### What it does
- Starts a TLS-wrapped TCP server
- Stores users in SQLite (`classical_users.db`)
- Hashes passwords with bcrypt
- Validates username/password over encrypted channel

### Requirements
- Python 3.9+
- OpenSSL (to generate certs)
- Python packages:
  ```bash
  pip install bcrypt
  ```

### Generate RSA certs
Run these in your project directory:

```bash
openssl genrsa -out rsa_server.key 2048
openssl req -new -key rsa_server.key -out rsa_server.csr
openssl x509 -req -days 365 -in rsa_server.csr -signkey rsa_server.key -out rsa_server.crt
```

This produces:
- `rsa_server.key`
- `rsa_server.crt`

### Run server
```bash
python classical_server.py
```

Server listens on:
- `0.0.0.0:4443`

### Test with OpenSSL client
```bash
openssl s_client -connect 127.0.0.1:4443
```

Default demo user:
- **username:** `alice`
- **password:** `Password123!`

---

## 2) Post-Quantum Login (Dilithium2 Challenge-Response)

### What it does
- Client generates Dilithium2 keypair
- Client registers its **public key**
- Server issues a random challenge
- Client signs challenge with **secret key**
- Server verifies signature using stored public key

### Requirements
- Python 3.9+
- Python packages:
  ```bash
  pip install flask requests dilithium
  ```

> Note: `dilithium` package name may vary by environment.  
> If install fails, check the report’s PQC library reference or substitute another Dilithium implementation.

### Run PQC server
```bash
python pqc_login.py
```

Server runs at:
- `http://0.0.0.0:60000`

### Run PQC client
In another terminal:

```bash
python pqc_client.py
```

Expected flow:
1. Client registers key
2. Client requests challenge
3. Client signs challenge
4. Server verifies and returns success

---

## Security Notes (Demo Scope)

- **Classical server** is a minimal demo:
  - No rate-limiting
  - No account lockout
  - No secure session/token after login
- **PQC server** stores keys/challenges **in memory only**:
  - Restarting server clears all users
  - No persistence layer added (demo simplicity)

---

## License

Use freely for academic, demo, or research purposes.  
If you publish or reuse, please cite the original report/project.
