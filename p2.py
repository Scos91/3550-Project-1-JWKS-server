from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

#connect to db
conn = sqlite3.connect('totally_not_my_privateKeys.db')

#create table
create_table_query = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)"""
conn.execute(create_table_query)

#change RSA to PEM form
def serialize_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

#save private key and exp time to db
def save_key_to_db(private_key_pem, expire_at):
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (private_key_pem, int(expire_at.timestamp())))
    conn.commit()
    return cursor.lastrowid

#manages generate and retreive of RSA
class KeyKeeper:
    def __init__(self):
        self.keys = []

    #generate RSA key pair w/ associated exp
    def genKey(self, is_expired=False):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        expire_at = now - datetime.timedelta(hours=1) if is_expired else now + datetime.timedelta(hours=1)

        private_key_pem = serialize_key(private_key)
        save_key_to_db(private_key_pem, expire_at)

        kid = save_key_to_db(private_key_pem, expire_at)

        return kid

    #return 1st active - not exp key
    def getActiveKey():
        cursor = conn.cursor()
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1", (now,))
        row = cursor.fetchone()
        if row:
            kid, private_key_pem, exp = row[0], row[1], int(row[2])
            return {'kid': kid, 'private_key_pem': private_key_pem, 'exp': exp}
        else:
            print("No Active Key Found.")
        return None

    #find key via kid
    def getKeyByKid(kid, expired=False):
        cursor = conn.cursor()
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        condition = "exp <= ?" if expired else "exp > ?"
        cursor.execute(f"SELECT kid, key FROM keys WHERE kid = ? AND {condition} LIMIT 1", (kid, now))
        row = cursor.fetchone()
        if row:
            return {'kid': row[0], 'private_key_pem': row[1]}
        else:
            print(f"No Key Found for Kid: {kid}, expired={'yes' if expired else 'no'}")
        return None

#convert int to base64 URL encode str
def intToBase64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

#gen JWT with private key and payload
def generate_jwt(private_key_pem, payload, kid):
    headers = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": str(kid)
    }
    private_key = load_pem_private_key(private_key_pem, password=None)
    encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
    return encoded_jwt

#init manager and gen keys
key_keeper = KeyKeeper()
key_keeper.genKey(is_expired=False)
key_keeper.genKey(is_expired=True)

#handle HTTP req for JWT auth and serve JWKS
class MyServer(BaseHTTPRequestHandler):

    #send 405 response w/ allowed methods
    def sendMethodInvalid(self, allowed_methods):
        self.send_response(405)
        self.send_header('Allow', ', '.join(allowed_methods))
        self.end_headers()

    #handle POST req - JWT given
    def do_POST(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/auth":
            params = parse_qs(parsed_path.query)
            expired = 'expired' in params and params['expired'][0] == 'true'

            if expired:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(bytes("Unauthorized: No valid key found.", "utf-8"))
                return

            #continue based on active or exp. key
            key = KeyKeeper.getActiveKey()
            if key is None:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(bytes("Internal server error: No valid key found.", "utf-8"))
                return

            #prepare the JWT payload
            token_payload = {
                "user": "username",
                "exp": int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).timestamp())
            }

            #gen. and return JWT
            try:
                encoded_jwt = generate_jwt(key['private_key_pem'], token_payload, str(key['kid']))
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = json.dumps({"token": encoded_jwt})
                self.wfile.write(bytes(response, "utf-8"))
            except Exception as e:
                print(f"Error in do_POST: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(bytes(f"Internal server error: {str(e)}", "utf-8"))

    #handle GET req - serve JWKS endpt
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            #retrieve all valid keys
            cursor = conn.cursor()
            now = datetime.datetime.now(datetime.timezone.utc).timestamp()
            cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))

            #construct JWKS response
            keys_info = []
            for row in cursor.fetchall():
                kid, private_key_pem = row
                private_key = load_pem_private_key(private_key_pem, password=None)
                public_key = private_key.public_key()
                public_numbers = public_key.public_numbers()

                keys_info.append({
                    "kty": "RSA",
                    "kid": str(kid),
                    "use": "sig",
                    "n": intToBase64(public_numbers.n),
                    "e": intToBase64(public_numbers.e),
                })

            keys = {"keys": keys_info}
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))

            return

    #handle HEAD req - treat like GET response for JWKS
    def do_HEAD(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            return
        self.sendMethodInvalid(['GET', 'POST'])

    #handle other methods
    def do_PUT(self): self.sendMethodInvalid(['GET', 'POST'])
    def do_DELETE(self): self.sendMethodInvalid(['GET', 'POST'])
    def do_PATCH(self): self.sendMethodInvalid(['GET', 'POST'])
    def do_OPTIONS(self): self.sendMethodInvalid(['GET', 'POST'])

if __name__ == "__main__":
    hostName = "localhost"
    serverPort = 8080
    webServer = HTTPServer((hostName, serverPort), MyServer)

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        webServer.server_close()
        conn.close()
