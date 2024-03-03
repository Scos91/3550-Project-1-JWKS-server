from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime

#server config
hostName = "localhost"
serverPort = 8080

#manages generate and retreive of RSA
class KeyKeeper:
    def __init__(self):
        self.keys = []

    #generate RSA key pair w/ associated exp
    def genKey(self, kid, is_expired=False):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        now = datetime.datetime.now(datetime.timezone.utc)
        if is_expired:
            expire_at = now - datetime.timedelta(hours=1)
        else:
            expire_at = now + datetime.timedelta(hours=1)

        self.keys.append({
            'kid': kid,
            'private_key': private_key,
            'public_key': public_key,
            'expire_at': expire_at
        })

    #return 1st active (not exp) key
    def getActiveKey(self):
        for key in self.keys:
            if key['expire_at'] > datetime.datetime.now(datetime.timezone.utc):
                return key
        return None

    #find key via kid
    def getKeyByKid(self, kid):
        for key in self.keys:
            if key['kid'] == kid:
                return key
        return None

#convert int to base64 URL encode str
def intToBase64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

#init manager and gen keys
key_keeper = KeyKeeper()
key_keeper.genKey('goodKID', is_expired=False)
key_keeper.genKey('expiredKID', is_expired=True)

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
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            key = key_keeper.getKeyByKid('expiredKID') if 'expired' in params and params['expired'][0] == 'true' else key_keeper.getActiveKey()
            if key is None:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(bytes("Internal server error: No valid key found.", "utf-8"))
                return

            private_key_pem = key['private_key'].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            exp_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1) if 'expired' in params and params['expired'][0] == 'true' else datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
            token_payload = {
                "user": "username",
                "exp": exp_time
            }
            encoded_jwt = jwt.encode(token_payload, private_key_pem, algorithm="RS256", headers={"kid": key['kid']})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return
        self.sendMethodInvalid(['GET'])

    #handle GET req - serve JWKS endpt
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys_info = []
            for key in key_keeper.keys:
                if key['expire_at'] > datetime.datetime.now(datetime.timezone.utc):
                    public_numbers = key['public_key'].public_numbers()
                    keys_info.append({
                        "kty": "RSA",
                        "kid": key['kid'],
                        "use": "sig",
                        "n": intToBase64(public_numbers.n),
                        "e": intToBase64(public_numbers.e),
                    })
            keys = {"keys": keys_info}
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return
        self.sendMethodInvalid(['POST'])

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
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
