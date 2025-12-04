import os  # optional env/path use
import requests  # HTTP client
from dilithium import Dilithium2  # Dilithium keygen/signing

SERVER = "http://127.0.0.1:60000"
USERNAME = "alice-pqc"


def generate_keys():
    """Create a Dilithium2 keypair."""
    sk = Dilithium2.secret_key()
    pk = sk.public_key()
    return sk, pk


def register_public_key(pk):
    """Send pk to server for registration."""
    payload = {
        "username": USERNAME,
        "public_key": pk.hex()
    }
    r = requests.post(f"{SERVER}/register", json=payload)
    return r.json()


def get_challenge():
    """Request challenge."""
    params = {"username": USERNAME}
    r = requests.get(f"{SERVER}/challenge", params=params)
    return r.json()


def submit_login(sk, ch_hex):
    """Sign challenge and submit signature."""
    ch = bytes.fromhex(ch_hex)
    sig = sk.sign(ch)

    payload = {
        "username": USERNAME,
        "signature": sig.hex()
    }
    r = requests.post(f"{SERVER}/login", json=payload)
    return r.json()


def main():
    sk, pk = generate_keys()

    reg = register_public_key(pk)
    print("Register:", reg)

    ch_resp = get_challenge()
    if ch_resp.get("status") != "ok":
        print("Challenge error:", ch_resp)
        return

    login_resp = submit_login(sk, ch_resp["challenge"])
    print("Login:", login_resp)


if __name__ == "__main__":
    main()
