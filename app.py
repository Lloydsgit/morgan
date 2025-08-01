import os
import json
import hashlib
import random
import logging
import socket
import threading
from decimal import Decimal
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, session, url_for, flash

# --- CONFIG & SETUP ---

app = Flask(__name__)
app.secret_key = 'rutland_secret_key_8583'
logging.basicConfig(level=logging.INFO)

# User login
USERNAME = "blackrock"
PASSWORD_FILE = "password.json"
CONFIG_FILE = "config.json"

# ISO8583 TCP Server config (for the *internal* dummy server)
# This internal server will run on 0.0.0.0:8583 within your Render service.
# It's used for local testing or if no external ISO server is configured.
INTERNAL_ISO_SERVER_HOST = "0.0.0.0"
INTERNAL_ISO_SERVER_PORT = 8583

# DEBUG Mode - primarily for any remaining debug logic.
DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"

# --- PASSWORD MANAGEMENT ---

if not os.path.exists(PASSWORD_FILE):
    with open(PASSWORD_FILE, "w") as f:
        hashed = hashlib.sha256("Br_3339".encode()).hexdigest()
        json.dump({"password": hashed}, f)

def check_password(raw):
    with open(PASSWORD_FILE) as f:
        stored = json.load(f)['password']
    return hashlib.sha256(raw.encode()).hexdigest() == stored

def set_password(newpass):
    with open(PASSWORD_FILE, "w") as f:
        hashed = hashlib.sha256(newpass.encode()).hexdigest()
        json.dump({"password": hashed}, f)

# --- LOGIN DECORATOR ---

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("You must be logged in.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

DUMMY_CARDS = {
    "4114755393849011": {"expiry": "0926", "cvv": "363", "auth": "1942", "type": "POS-101.1"},
    "4000123412341234": {"expiry": "1126", "cvv": "123", "auth": "4021", "type": "POS-101.1"},
    "4117459374038454": {"expiry": "1026", "cvv": "258", "auth": "384726", "type": "POS-101.4"},
    "4123456789012345": {"expiry": "0826", "cvv": "852", "auth": "495128", "type": "POS-101.4"},
    "5454957994741066": {"expiry": "1126", "cvv": "746", "auth": "627192", "type": "POS-101.6"},
    "6011000990131077": {"expiry": "0825", "cvv": "330", "auth": "8765", "type": "POS-101.7"},
    "3782822463101088": {"expiry": "1226", "cvv": "1059", "auth": "0000", "type": "POS-101.8"},
    "3530760473041099": {"expiry": "0326", "cvv": "244", "auth": "712398", "type": "POS-201.1"},
    "4114938274651920": {"expiry": "0926", "cvv": "463", "auth": "3127", "type": "POS-101.1"},
    "4001948263728191": {"expiry": "1026", "cvv": "291", "auth": "574802", "type": "POS-101.4"},
    "6011329481720394": {"expiry": "0825", "cvv": "310", "auth": "8891", "type": "POS-101.7"},
    "378282246310106":  {"expiry": "1226", "cvv": "1439", "auth": "0000", "type": "POS-101.8"},
    "3531540982734612": {"expiry": "0326", "cvv": "284", "auth": "914728", "type": "POS-201.1"},
    "5456038291736482": {"expiry": "1126", "cvv": "762", "auth": "695321", "type": "POS-201.3"},
    "4118729301748291": {"expiry": "1026", "cvv": "249", "auth": "417263", "type": "POS-201.5"}
}


PROTOCOLS = {
    "POS Terminal -101.1 (4-digit approval)": 4,
    "POS Terminal -101.4 (6-digit approval)": 6,
    "POS Terminal -201.1 (6-digit approval)": 6,
    "POS Terminal -101.7 (4-digit approval)": 4,
    "POS Terminal -101.8 (PIN-LESS transaction)": 4,
    "POS Terminal -201.3 (6-digit approval)": 6,
    "POS Terminal -201.5 (6-digit approval)": 6
}

FIELD_39_RESPONSES = {
    "00": "Approved",
    "05": "Do Not Honor",
    "54": "Expired Card",
    "82": "Invalid CVV",
    "91": "Issuer Inoperative",
    "92": "Invalid Terminal Protocol",
    "99": "System Error"
}

# --- LOAD CONFIG ---

def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            # These are YOUR receiving wallet addresses
            json.dump({
                "my_erc20_wallet": "0xYourERC20ReceivingAddressHere",
                "my_trc20_wallet": "TYourTRC20ReceivingAddressHere"
            }, f, indent=4) # Added indent for readability
    with open(CONFIG_FILE) as f:
        return json.load(f)

CONFIG = load_config()

# --- ISO8583 TCP SERVER (Background Thread) ---
# This server is for internal simulation if no external ISO server is configured.
def iso8583_server_thread(host=INTERNAL_ISO_SERVER_HOST, port=INTERNAL_ISO_SERVER_PORT):
    def server():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set SO_REUSEADDR to allow immediate reuse of the port
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.listen()
            logging.info(f"ISO8583 Server listening on {host}:{port}")
            while True:
                conn, addr = s.accept()
                with conn:
                    logging.info(f"ISO8583 client connected from {addr}")
                    while True:
                        data = conn.recv(2048)
                        if not data:
                            break
                        logging.info(f"Received ISO8583 data: {data}")

                        data_str = data.decode(errors='ignore').strip()

                        # Detect HTTP request and ignore/close connection
                        if data_str.startswith(("GET ", "POST ", "HEAD ", "OPTIONS ")):
                            logging.warning(f"Received HTTP request on ISO8583 port from {addr}, closing connection.")
                            # No response for HTTP requests, just close the connection
                            break  # Close connection

                        # Process ISO8583 JSON message
                        try:
                            msg = json.loads(data_str)
                            pan = msg.get("pan")
                            expiry = msg.get("expiry")
                            cvv = msg.get("cvv")
                            amount = msg.get("amount")

                            # Dummy auth logic: check PAN in DUMMY_CARDS and match expiry/cvv
                            card = DUMMY_CARDS.get(pan)
                            if not card:
                                response = {"approved": False, "field39": "05"}  # Do Not Honor
                            elif card["expiry"] != expiry:
                                response = {"approved": False, "field39": "54"}  # Expired Card
                            elif card["cvv"] != cvv:
                                response = {"approved": False, "field39": "82"}  # Invalid CVV
                            else:
                                response = {"approved": True, "field39": "00"}

                        except json.JSONDecodeError:
                            logging.error(f"Invalid JSON received on ISO8583 port from {addr}: {data_str}")
                            response = {"approved": False, "field39": "99"} # System Error
                        except Exception as e:
                            logging.error(f"Error processing ISO8583 request: {e}")
                            response = {"approved": False, "field39": "99"}

                        response_raw = json.dumps(response).encode()
                        conn.sendall(response_raw)

    threading.Thread(target=server, daemon=True).start()
    
iso8583_server_thread()

# --- ISO8583 CLIENT FUNCTION ---

def send_iso_authorization(pan, expiry, cvv, amount_cents):
    # Get external ISO server details from environment variables,
    # falling back to the internal server's config if not set.
    external_iso_host = os.getenv("EXTERNAL_ISO_SERVER_HOST", INTERNAL_ISO_SERVER_HOST)
    external_iso_port = int(os.getenv("EXTERNAL_ISO_SERVER_PORT", INTERNAL_ISO_SERVER_PORT))

    msg = {
        "mti": "0100",
        "pan": pan,
        "expiry": expiry,
        "cvv": cvv,
        "amount": amount_cents
    }
    logging.info(f"Connecting to ISO server at {external_iso_host}:{external_iso_port}")
    with socket.create_connection((external_iso_host, external_iso_port), timeout=10) as sock:
        raw = json.dumps(msg).encode()
        sock.sendall(raw)
        resp = sock.recv(4096)
        if not resp:
            raise Exception("No response from ISO server")
        decoded = json.loads(resp.decode())
        logging.info(f"ISO8583 Response: {decoded}")
        return decoded

# --- FLASK ROUTES ---

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        passwd = request.form.get('password')
        if user == USERNAME and check_password(passwd):
            session['logged_in'] = True
            return redirect(url_for('protocol'))
        flash("Invalid username or password.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current')
        newpass = request.form.get('new')
        if not check_password(current):
            flash("Current password incorrect.")
            return render_template('change_password.html')
        set_password(newpass)
        flash("Password changed successfully.")
    return render_template('change_password.html')

@app.route('/protocol', methods=['GET', 'POST'])
@login_required
def protocol():
    if request.method == 'POST':
        selected = request.form.get('protocol')
        if selected not in PROTOCOLS:
            return redirect(url_for('rejected', code="92", reason=FIELD_39_RESPONSES["92"]))
        session['protocol'] = selected
        session['code_length'] = PROTOCOLS[selected]
        return redirect(url_for('amount'))
    return render_template('protocol.html', protocols=PROTOCOLS.keys())

@app.route('/amount', methods=['GET', 'POST'])
@login_required
def amount():
    if request.method == 'POST':
        amt = request.form.get('amount')
        # basic validation could be added here
        session['amount'] = amt
        # Directly move to card input after amount, skipping payout type selection
        return redirect(url_for('card'))
    return render_template('amount.html')

# Removed the /payout route entirely as it's no longer needed for user input.

@app.route('/card', methods=['GET', 'POST'])
@login_required
def card():
    if request.method == 'POST':
        pan = request.form.get('pan')
        expiry = request.form.get('expiry')
        cvv = request.form.get('cvv')

        # Optionally validate here

        session['pan'] = pan
        session['expiry'] = expiry
        session['cvv'] = cvv
        return redirect(url_for('auth'))
    return render_template('card.html')

@app.route('/auth', methods=['GET', 'POST'])
@login_required
def auth():
    if request.method == 'POST':
        auth_code = request.form.get('auth_code')
        expected_len = session.get('code_length', 4)

        if not auth_code or len(auth_code) != expected_len:
            flash(f"Authorization code must be {expected_len} digits.")
            return redirect(url_for('auth'))

        session['auth_code'] = auth_code
        session['txn_id'] = f"TXN{random.randint(100000, 999999)}"
        session['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Prepare ISO8583 authorization request
        pan = session['pan']
        expiry = session['expiry']
        cvv = session['cvv']
        amount = session['amount']

        amount_decimal = Decimal(amount)
        amount_cents = int(amount_decimal * 100)

        # 1) Send ISO8583 authorization
        try:
            auth_resp = send_iso_authorization(pan, expiry, cvv, amount_cents)
        except Exception as e:
            flash(f"ISO8583 server error: {str(e)}")
            return redirect(url_for('auth'))

        if not auth_resp.get('approved'):
            code = auth_resp.get('field39', '99')
            reason = FIELD_39_RESPONSES.get(code, "Unknown error")
            flash(f"Transaction rejected: {reason} (code {code})")
            return redirect(url_for('auth'))

        # 2) Card authorization approved. Funds are expected to be received by your configured wallet.
        # No automated crypto payout from your side.
        session['receiving_wallet_info'] = {
            "erc20": CONFIG.get("my_erc20_wallet", "Not Configured"),
            "trc20": CONFIG.get("my_trc20_wallet", "Not Configured")
        }
        flash("Card authorized successfully. Funds are expected to be received in your configured wallet.")
        return redirect(url_for('success'))

    return render_template('auth.html', code_length=session.get('code_length', 4))

@app.route('/success')
@login_required
def success():
    return render_template('success.html',
                           txn_id=session.get('txn_id'),
                           pan=session.get('pan'),
                           amount=session.get('amount'),
                           timestamp=session.get('timestamp'),
                           receiving_wallet_info=session.get('receiving_wallet_info'))

@app.route('/rejected/<code>/<reason>')
def rejected(code, reason):
    return render_template('rejected.html', code=code, reason=reason)

@app.route('/health')
def health_check():
    # This endpoint is crucial for Render's health checks
    return "OK", 200

# --- PASSWORD RESET ---

@app.route('/reset-password-request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        token = request.form.get('reset_token')
        if token == os.getenv("RESET_TOKEN", "adminreset123"):
            session['allow_reset'] = True
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid reset token")
    return render_template('reset_password_request.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if not session.get('allow_reset'):
        flash("Unauthorized")
        return redirect(url_for('reset_password_request'))

    if request.method == 'POST':
        newpass = request.form.get('new_password')
        set_password(newpass)
        session.pop('allow_reset', None)
        flash("Password reset successful")
        return redirect(url_for('login'))
    return render_template('reset_password.html')

# --- RUN APP ---

if __name__ == "__main__":
    # Render provides the PORT environment variable.
    # Your Flask app MUST listen on this port to be accessible as a web service.
    port = int(os.getenv("PORT", 5000)) # Default to 5000 for local testing if PORT not set
    app.run(host="0.0.0.0", port=port, debug=True)
