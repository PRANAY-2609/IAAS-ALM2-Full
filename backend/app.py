from flask import Flask, jsonify, request
from flask_cors import CORS
import secrets

app = Flask(__name__)
CORS(app)

TLS_STEPS = [
    {"title": "1. Client Hello", "from": "Client", "to": "Server",
     "detail": "The client proposes supported protocol versions and cipher suites."},
    {"title": "2. Server Hello & Certificate", "from": "Server", "to": "Client",
     "detail": "The server selects parameters and presents a certificate. This demo does not validate a real certificate."},
    {"title": "3. Client Key Exchange", "from": "Client", "to": "Server",
     "detail": "Conceptual step: the client sends key-establishment data. Modern TLS commonly uses ephemeral Diffie–Hellman rather than RSA key transport."},
    {"title": "4. Session Key Generation", "from": "Both", "to": "Both",
     "detail": "Both sides derive matching symmetric session keys from the negotiated key material."},
    {"title": "5. Finished", "from": "Both", "to": "Both",
     "detail": "Both sides confirm the handshake transcript and the secure channel is ready in this simplified model."}
]
SSH_STEPS = [
    {"title": "1. Protocol Version Exchange", "from": "Client", "to": "Server",
     "detail": "Client and server announce compatible SSH protocol versions."},
    {"title": "2. Key Exchange", "from": "Both", "to": "Both",
     "detail": "A Diffie–Hellman-style exchange is used to derive shared session material."},
    {"title": "3. Server Authentication", "from": "Server", "to": "Client",
     "detail": "The client checks the server host key against a trusted record (simulated here)."},
    {"title": "4. User Authentication", "from": "Client", "to": "Server",
     "detail": "The user is authenticated. This demo uses a simulated success/failure choice."},
    {"title": "5. Secure Channel Established", "from": "Both", "to": "Both",
     "detail": "Encrypted communication can now take place in the conceptual model."}
]

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "project": "SecureTunnel"})

@app.get("/api/handshake/<protocol>")
def handshake(protocol):
    if protocol.lower() == "tls":
        return jsonify({"protocol": "TLS", "steps": TLS_STEPS})
    if protocol.lower() == "ssh":
        return jsonify({"protocol": "SSH", "steps": SSH_STEPS})
    return jsonify({"error": "Protocol must be tls or ssh"}), 404

@app.post("/api/session-demo")
def session_demo():
    data = request.get_json(silent=True) or {}
    authenticated = bool(data.get("authenticated", True))
    # This is a random demo token, not a cryptographic TLS session key.
    return jsonify({
        "authenticated": authenticated,
        "channel": "established" if authenticated else "not established",
        "demo_session_id": secrets.token_hex(8) if authenticated else None,
        "note": "Illustrative simulation only; this value is not a real TLS session key."
    })

@app.post("/api/ipsec")
def ipsec():
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "transport")
    if mode not in ("transport", "tunnel"):
        return jsonify({"error": "mode must be transport or tunnel"}), 400
    packet = {
        "mode": mode,
        "outer_ip_header": "New outer IP header" if mode == "tunnel" else "Original IP header remains",
        "esp_header": "ESP header added",
        "payload": "Original IP payload (encrypted in a real ESP protected packet)",
        "esp_trailer": "ESP trailer and authentication data added",
        "explanation": ("Tunnel mode protects the complete original IP packet inside a new outer IP packet."
                       if mode == "tunnel" else
                       "Transport mode protects the IP payload while the original IP header remains visible.")
    }
    return jsonify(packet)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
