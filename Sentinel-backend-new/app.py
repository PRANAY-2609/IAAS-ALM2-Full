from flask import Flask, jsonify, request
from flask_cors import CORS
from collections import Counter
from statistics import mean, pstdev
from datetime import datetime, timezone
import ipaddress

app = Flask(__name__)
CORS(app)
rules = [
    {"id": 1, "action": "block", "source_ip": "192.168.1.100", "port": "*", "protocol": "*", "description": "Block example suspicious host"},
    {"id": 2, "action": "allow", "source_ip": "*", "port": "80", "protocol": "TCP", "description": "Allow HTTP"}
]
events = []
alerts = []
next_rule_id = 3
source_counts = Counter()

def alert(kind, severity, message, source_ip):
    alerts.insert(0, {"id": len(alerts)+1, "time": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                      "type": kind, "severity": severity, "message": message, "source_ip": source_ip})
    del alerts[100:]

def validate_ip(value):
    if value == "*":
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def evaluate(packet):
    # First matching rule wins; a missing match defaults to allow for this educational demo.
    for rule in rules:
        if (rule["source_ip"] in ("*", packet["source_ip"]) and
            rule["port"] in ("*", str(packet["port"])) and
            rule["protocol"] in ("*", packet["protocol"].upper())):
            return rule["action"], rule
    return "allow", None

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "project": "Sentinel"})

@app.get("/api/rules")
def get_rules():
    return jsonify(rules)

@app.post("/api/rules")
def add_rule():
    global next_rule_id
    data = request.get_json(silent=True) or {}
    action = str(data.get("action", "block")).lower()
    source_ip = str(data.get("source_ip", "*")).strip()
    port = str(data.get("port", "*")).strip()
    protocol = str(data.get("protocol", "*")).upper()
    description = str(data.get("description", "Custom rule")).strip()[:120]
    if action not in ("allow", "block"):
        return jsonify({"error": "Action must be allow or block"}), 400
    if not validate_ip(source_ip):
        return jsonify({"error": "Enter a valid IPv4/IPv6 address or *"}), 400
    if port != "*" and (not port.isdigit() or not 1 <= int(port) <= 65535):
        return jsonify({"error": "Port must be * or a number from 1 to 65535"}), 400
    if protocol not in ("*", "TCP", "UDP", "ICMP"):
        return jsonify({"error": "Protocol must be *, TCP, UDP, or ICMP"}), 400
    item = {"id": next_rule_id, "action": action, "source_ip": source_ip, "port": port,
            "protocol": protocol, "description": description or "Custom rule"}
    next_rule_id += 1
    rules.insert(0, item)
    return jsonify(item), 201

@app.delete("/api/rules/<int:rule_id>")
def delete_rule(rule_id):
    global rules
    before = len(rules)
    rules = [r for r in rules if r["id"] != rule_id]
    if len(rules) == before:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify({"deleted": rule_id})

@app.get("/api/alerts")
def get_alerts():
    return jsonify(alerts)

@app.get("/api/stats")
def get_stats():
    counts = Counter(e["source_ip"] for e in events)
    return jsonify({"total_events": len(events), "total_alerts": len(alerts),
                    "sources": [{"source_ip": k, "packets": v} for k,v in counts.items()]})

@app.post("/api/traffic")
def traffic():
    data = request.get_json(silent=True) or {}
    kind = str(data.get("kind", "HTTP")).upper()
    source_ip = str(data.get("source_ip", "10.0.0.10")).strip()
    if not validate_ip(source_ip) or source_ip == "*":
        return jsonify({"error": "Enter a valid source IP address"}), 400
    choices = {"HTTP": (80, "TCP"), "SSH_SUCCESS": (22, "TCP"),
               "SSH_FAIL": (22, "TCP"), "TELNET": (23, "TCP"),
               "UDP": (53, "UDP"), "PORT_SCAN": (4444, "TCP")}
    if kind not in choices:
        return jsonify({"error": "Unsupported traffic type"}), 400
    port, protocol = choices[kind]
    packet = {"source_ip": source_ip, "port": port, "protocol": protocol, "kind": kind,
              "time": datetime.now(timezone.utc).strftime("%H:%M:%S UTC")}
    action, matched_rule = evaluate(packet)
    packet["firewall_action"] = action
    packet["matched_rule"] = matched_rule["description"] if matched_rule else "Default allow (no matching rule)"
    events.insert(0, packet)
    del events[200:]
    source_counts[source_ip] += 1

    if action == "block":
        alert("Firewall", "High", f"Traffic blocked by rule: {packet['matched_rule']}", source_ip)
    if kind == "TELNET":
        alert("Rule-based IDS", "High", "Suspicious Telnet traffic detected on port 23", source_ip)
    if kind == "PORT_SCAN":
        alert("Rule-based IDS", "Medium", "Simulated unusual port activity detected", source_ip)
    if kind == "SSH_FAIL":
        recent_fails = sum(1 for e in events[:100] if e["source_ip"] == source_ip and e["kind"] == "SSH_FAIL")
        if recent_fails >= 5:
            alert("Rule-based IDS", "High", f"{recent_fails} failed SSH attempts from the same IP", source_ip)

    # Statistical anomaly: compare this source's packet count to historical source counts.
    values = list(source_counts.values())
    if len(values) >= 2:
        avg = mean(values)
        sd = pstdev(values)
        if sd > 0 and source_counts[source_ip] > avg + 3 * sd:
            alert("Anomaly IDS", "Medium", "Source packet count is more than 3 standard deviations above the mean", source_ip)

    return jsonify({"packet": packet, "alerts": alerts[:10], "stats": {"events": len(events), "alerts": len(alerts)}}), 201

@app.post("/api/reset")
def reset():
    events.clear()
    alerts.clear()
    source_counts.clear()
    return jsonify({"reset": True})

@app.get("/api/threats")
def threats():
    return jsonify([
      {"name":"File-infector virus","type":"Virus","description":"Attaches to executable files and may spread when an infected file runs.","countermeasure":"Use reputable endpoint protection; avoid untrusted executables; keep backups."},
      {"name":"Boot-sector virus","type":"Virus","description":"Targets boot-related storage areas and can interfere with system startup.","countermeasure":"Keep systems patched and use trusted recovery media."},
      {"name":"Email worm","type":"Worm","description":"Self-propagating malware that may spread through malicious attachments or links.","countermeasure":"Verify unexpected attachments, filter email, and keep software updated."},
      {"name":"Network worm","type":"Worm","description":"Can spread between systems by exploiting vulnerable services.","countermeasure":"Patch services, segment networks, restrict exposed ports, and monitor alerts."}
    ])

@app.get("/api/events")
def get_events():
    return jsonify(events)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
