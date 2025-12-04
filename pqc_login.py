import os  # environment utilities
import secrets  # cryptographically secure randomness
from flask import Flask, request, jsonify  # REST API
from dilithium import Dilithium2, VerifyKey  # Dilithium signatures + verification

app = Flask("pqc_login")

# In-memory stores (demo)
users = {}        # username -> public key (hex)
challenges = {}   # username -> active challenge (bytes)


def generate_challenge():
    """Create a fresh unpredictable challenge."""
    return secrets.token_bytes(32)


@app.post("/register")
def register():
    """Register a user's public key."""
    data = request.get_json(force=True)
    username = data.get("username")
    public_key_hex = data.get("public_key")

    if not username or not public_key_hex:
        return jsonify({"status": "error",
                        "msg": "username and public_key required"}), 400
    try:
        # Validate public key
        _vk = VerifyKey.from_hex(public_key_hex)
        users[username] = public_key_hex
        return jsonify({"status": "registered"})
    except Exception:
        return jsonify({"status": "error", "msg": "invalid public_key"}), 400


@app.get("/challenge")
def challenge():
    """Issue a per-user challenge to be signed."""
    username = request.args.get("username")
    if not username:
        return jsonify({"status": "error", "msg": "username required"}), 400
    if username not in users:
        return jsonify({"status": "error", "msg": "unknown user"}), 404

    ch = generate_challenge()
    challenges[username] = ch
    return jsonify({"status": "ok", "challenge": ch.hex()})


@app.post("/login")
def login():
    """Verify signed challenge."""
    data = request.get_json(force=True)
    username = data.get("username")
    signature_hex = data.get("signature")

    if not username or not signature_hex:
        return jsonify({"status": "error",
                        "msg": "username and signature required"}), 400
    if username not in users:
        return jsonify({"status": "error", "msg": "unknown user"}), 404

    ch = challenges.get(username)
    if not ch:
        return jsonify({"status": "error", "msg": "no active challenge"}), 400

    try:
        vk = VerifyKey.from_hex(users[username])
        sig = bytes.fromhex(signature_hex)
        ok = vk.verify(ch, sig)

        if ok:
            challenges.pop(username, None)
            return jsonify({"status": "success"})
        else:
            return jsonify({"status": "error",
                            "msg": "invalid signature"}), 401
    except Exception:
        return jsonify({"status": "error",
                        "msg": "verification failure"}), 400


if __name__ == "__main__":
    host = "0.0.0.0"
    port = 60000
    app.run(host=host, port=port, debug=False)
