import unittest
import requests
import jwt
import json
import base64

class ServerTestCase(unittest.TestCase):
    server_url = "http://localhost:8080"

    #test the JWKS endpt - return 200 and JSON
    def test_jwks_endpoint_success(self):
        response = requests.get(f'{self.server_url}/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers['Content-Type'].startswith('application/json'))
        data = response.json()
        self.assertIn('keys', data)
        self.assertIsInstance(data['keys'], list)

    #test the auth endpt - return 200 and JWT
    def test_auth_endpoint_success(self):
        response = requests.post(f'{self.server_url}/auth')
        self.assertEqual(response.status_code, 200)
        token = response.text
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            self.assertIn('exp', decoded)
        except jwt.DecodeError:
            self.fail("Failed to decode JWT")

    #test auth endpt - return exp JWT
    def test_auth_endpoint_expired_token(self):
        response = requests.post(f'{self.server_url}/auth?expired=true')
        self.assertEqual(response.status_code, 401, "Should return 401 for expired token")

    #test invalid method - auth return 405
    def test_unsupported_method_on_auth(self):
        response = requests.get(f'{self.server_url}/auth')
        self.assertEqual(response.status_code, 405)

    #test invalid method - JWKS endpt return 405
    def test_unsupported_method_on_jwks(self):
        response = requests.post(f'{self.server_url}/.well-known/jwks.json')
        self.assertEqual(response.status_code, 405)

    #test req unknown endpt - return 404
    def test_404_for_unknown_endpoint(self):
        response = requests.get(f'{self.server_url}/nonexistent')
        self.assertEqual(response.status_code, 404)

    #JWT validation test
    def test_jwt_structure_and_claims(self):
        response = requests.post(f'{self.server_url}/auth')
        self.assertEqual(response.status_code, 200)
        token = response.text

        #split JWT - verify header and payload
        parts = token.split('.')
        self.assertEqual(len(parts), 3, "JWT should have three parts")

        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8'))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8'))
        except Exception as e:
            self.fail(f"Failed to decode JWT parts: {e}")

if __name__ == '__main__':
    unittest.main()
