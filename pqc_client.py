import requests  # Importing requests to send HTTP calls to the PQC server endpoints
import oqs       # Importing Open Quantum Safe bindings to generate Dilithium2 keypairs and signatures

server_url = "https://localhost:6000"  # Defining the base URL of the PQC server (running with adhoc TLS)

# Create a Dilithium2 signature object
sig = oqs.Signature("Dilithium2")  # Initialising Dilithium2 signature scheme

# Generate a keypair
public_key = sig.generate_keypair()  # Generating a new Dilithium2 public key
secret_key = sig.export_secret_key()  # Exporting the corresponding private key

username = "alice"  # Defining a demo username for registration

# Step 1: Register public key with server
resp = requests.post(f"{server_url}/register", json={
    "username": username,  # Sending username field
    "public_key": public_key.hex()  # Sending public key hex-encoded
}, verify=False)  # verify=False to skip TLS certificate validation in demo
print("Register:", resp.json())  # Printing server response

# Step 2: Request challenge from server
resp = requests.get(f"{server_url}/challenge", params={"username": username}, verify=False)
challenge_hex = resp.json().get("challenge")  # Extracting challenge string from server response
challenge = bytes.fromhex(challenge_hex)  # Converting hex challenge to raw bytes
print("Challenge:", challenge_hex)  # Printing challenge

# Step 3: Sign challenge with private key
signature = sig.sign(challenge)  # Signing the challenge using Dilithium2 private key

# Step 4: Submit signature to server for login
resp = requests.post(f"{server_url}/login", json={
    "username": username,  # Sending username field
    "challenge": challenge.decode(errors="ignore"),  # Sending challenge back (decoded to string for JSON)
    "signature": signature.hex()  # Sending signature hex-encoded
}, verify=False)
print("Login:", resp.json())  # Printing server response
