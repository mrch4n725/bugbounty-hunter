"""
mock_target.py — Flask-based mock vulnerable server for integration testing.

Routes:
  /xss?q=<payload>              — Reflected XSS
  /sqli?id=<payload>            — Simulated SQL error on '
  /jwt-none                     — Accepts alg:none JWT
  /null-token                   — 401 without token, 200 with null/empty
  /idor/<id>                    — Returns user data for any numeric ID
  /cors                         — Returns Access-Control-Allow-Origin: *
  /header-bypass                — 200 when X-Original-URL or X-Forwarded-For present
  /api/user                     — Returns JSON user data (for auth testing)
"""

from flask import Flask, request, jsonify, make_response
import jwt as pyjwt

app = Flask(__name__)

# Simulated user database
USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "user"},
    2: {"id": 2, "name": "Bob", "email": "bob@example.com", "role": "user"},
    3: {"id": 3, "name": "Charlie", "email": "charlie@example.com", "role": "admin"},
}

JWT_SECRET = "supersecretkey"


@app.route("/xss")
def xss():
    q = request.args.get("q", "")
    return f"<html><body>{q}</body></html>", 200, {"Content-Type": "text/html"}


@app.route("/sqli")
def sqli():
    id_val = request.args.get("id", "")
    if "'" in id_val or '"' in id_val:
        return (
            "<html><body>SQL syntax error: near '''' at line 1</body></html>",
            500,
            {"Content-Type": "text/html"},
        )
    if "sleep" in id_val.lower():
        import time
        time.sleep(5)
        return "<html><body>OK</body></html>", 200, {"Content-Type": "text/html"}
    return f"<html><body>User {id_val}</body></html>", 200, {"Content-Type": "text/html"}


@app.route("/jwt-none", methods=["GET", "POST"])
def jwt_none():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        try:
            header = pyjwt.get_unverified_header(token)
            if header.get("alg") == "none":
                payload = pyjwt.decode(token, options={"verify_signature": False})
                return jsonify({"status": "ok", "user": payload.get("sub", "unknown")})
        except Exception:
            pass
    return jsonify({"error": "unauthorized"}), 401


@app.route("/null-token")
def null_token():
    auth = request.headers.get("Authorization", "")
    if not auth or auth == "Bearer null" or auth == "Bearer undefined" or auth == "Bearer None":
        return jsonify({"status": "ok", "user": "admin"})
    if auth.startswith("Bearer "):
        return jsonify({"status": "ok", "user": "authenticated"})
    return jsonify({"error": "unauthorized"}), 401


@app.route("/idor/<int:user_id>")
def idor(user_id):
    user = USERS.get(user_id)
    if user:
        return jsonify(user)
    return jsonify({"error": "not found"}), 404


@app.route("/idor/<int:user_id>/profile")
def idor_profile(user_id):
    user = USERS.get(user_id)
    if user:
        return jsonify({
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "address": "123 Secret St",
            "phone": "+1-555-123-4567",
            "ssn": "XXX-XX-1234",
        })
    return jsonify({"error": "not found"}), 404


@app.route("/cors")
def cors():
    resp = make_response(jsonify({"message": "sensitive data"}))
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@app.route("/header-bypass")
def header_bypass():
    if request.headers.get("X-Original-URL") or request.headers.get("X-Forwarded-For"):
        return jsonify({"status": "ok", "admin_panel": "true"})
    return jsonify({"error": "forbidden"}), 403


@app.route("/api/user")
def api_user():
    return jsonify({
        "id": 1,
        "name": "Alice",
        "email": "alice@example.com",
        "role": "user",
    })


@app.route("/api/admin")
def api_admin():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and "admin" in auth.lower():
        return jsonify({"status": "ok", "secret": "flag_12345"})
    return jsonify({"error": "forbidden"}), 403


@app.route("/")
def index():
    return "<html><body><h1>Mock Target</h1></body></html>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=18999, debug=False)
