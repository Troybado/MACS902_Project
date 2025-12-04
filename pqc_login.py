from flask import Flask, request, jsonify  # Importing Flask and helpers to implement HTTP endpoints and JSON responses
import oqs  # Importing Open Quantum Safe bindings to access Dilithium2 signature functionality

app = Flask("pqc_login")  # Creating a Flask application instance with a descriptive name

users = {}  # Initialising an in-memory dictionary mapping username → public key (hex string)
challenges = {}  # Initialising an in-memory dictionary mapping username → active challenge (bytes) for login flow

sig = oqs.Signature("Dilithium2")  # Creating a Dilithium2 signature object for verification operations

def generate_challenge():  # Defining a helper function to create a fresh, unpredictable challenge
    return b"login_request"  # Returning a static challenge string for demo purposes (replace with random in production)

@app.post("/register")  # Defining a POST endpoint for public key registration
def register():  # Handler function for the /register endpoint
    data = request.get_json(force=True)  # Parsing JSON body; force=True to accept missing headers in demos
    username = data.get("username")  # Extracting the username field from the JSON payload
    public_key_hex = data.get("public_key")  # Extracting the public key as a hex-encoded string
    if not username or not public_key_hex:  # Validating required fields are present
        return jsonify({"status": "error", "msg": "username and public_key required"}), 400  # Returning HTTP 400 on bad request
    try:  # Attempting to parse and store the provided public key
        users[username] = public_key_hex  # Storing the hex-encoded public key for the user
        return jsonify({"status": "registered"})  # Returning success status
    except Exception as e:  # Catching any parsing or validation errors
        return jsonify({"status": "error", "msg": "invalid public_key"}), 400  # Returning a meaningful error message

@app.get("/challenge")  # Defining a GET endpoint to request a login challenge
def challenge():  # Handler for issuing a per-user challenge that must be signed
    username = request.args.get("username")  # Reading the username from the query string parameter
    if not username:  # Ensuring the client provided a username
        return jsonify({"status": "error", "msg": "username required"}), 400  # Responding with HTTP 400 for missing parameter
    if username not in users:  # Ensuring the user is registered before issuing a challenge
        return jsonify({"status": "error", "msg": "unknown user"}), 404  # Responding with HTTP 404 if the user is not found
    ch = generate_challenge()  # Creating a fresh challenge for this user
    challenges[username] = ch  # Storing the challenge server-side associated with the username
    return jsonify({"status": "ok", "challenge": ch.hex()})  # Returning the challenge to the client hex-encoded for transport

@app.post("/login")  # Defining a POST endpoint to submit a signature and complete authentication
def login():  # Handler for verifying the signed challenge from the client
    data = request.get_json(force=True)  # Parsing the JSON body from the client
    username = data.get("username")  # Extracting the username from the request body
    signature_hex = data.get("signature")  # Extracting signature as hex-encoded string
    if not username or not signature_hex:  # Validating required fields exist
        return jsonify({"status": "error", "msg": "username and signature required"}), 400  # Responding with HTTP 400 on invalid input
    if username not in users:  # Ensuring the user is registered
        return jsonify({"status": "error", "msg": "unknown user"}), 404  # Responding with HTTP 404 if the user is missing
    ch = challenges.get(username)  # Fetching the last issued challenge for this user
    if not ch:  # Ensuring a challenge exists (i.e., /challenge was called)
        return jsonify({"status": "error", "msg": "no active challenge"}), 400  # Responding with HTTP 400 if challenge is missing
    try:  # Attempting to verify the signature using stored public key
        public_key_bytes = bytes.fromhex(users[username])  # Converting stored hex public key back to raw bytes
        sig_bytes = bytes.fromhex(signature_hex)  # Decoding the signature from hex to raw bytes
        ok = sig.verify(ch, sig_bytes, public_key_bytes)  # Verifying the signature over the challenge; returns True if valid
        if ok:  # If verification succeeded
            challenges.pop(username, None)  # Consuming and clearing the challenge to prevent replay attacks
            return jsonify({"status": "success"})  # Responding that login is successful
        else:  # In case signature is invalid
            return jsonify({"status": "error", "msg": "invalid signature"}), 401  # Responding with HTTP 401 Unauthorised
    except Exception as e:  # Catching any errors in decoding or verifying
        return jsonify({"status": "error", "msg": "verification failure"}), 400  # Responding with a generic verification error

if __name__ == "__main__":  # Running the Flask development server only when executed directly
    host = "0.0.0.0"  # Binding to all network interfaces for demo accessibility
    port = 6000  # Choosing port 6000 for PQC server demo
    app.run(host=host, port=port, ssl_context="adhoc", debug=False)  # Starting the Flask app with ad-hoc TLS and debug disabled
