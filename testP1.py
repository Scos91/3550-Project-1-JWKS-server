import unittest
import requests
import jwt
import json

class ServerTestCase(unittest.TestCase):
    server_url = "http://localhost:8080"

    #test - JWKS endpt returns 200 and valid JSON
    def test_jwks_endpoint_success(self):
        response = requests.get(f'{self.server_url}/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers['Content-Type'].startswith('application/json'))
        data = response.json()
        self.assertIn('keys', data)
        self.assertIsInstance(data['keys'], list)

    #test - auth endpt returns 200 and valid JWT
    def test_auth_endpoint_success(self):
        response = requests.post(f'{self.server_url}/auth')
        self.assertEqual(response.status_code, 200)
        token = response.text
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            self.assertIn('exp', decoded)
        except jwt.DecodeError:
            self.fail("Failed to decode JWT")

    #test - auth endpt returns exp JWT
    def test_auth_endpoint_expired_token(self):
        response = requests.post(f'{self.server_url}/auth?expired=true')
        self.assertEqual(response.status_code, 200)
        token = response.text
        try:
            decoded = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
            self.assertIn('exp', decoded)
        except jwt.DecodeError:
            self.fail("Failed to decode JWT")

    #test - send invalid method to auth return 405
    def test_unsupported_method_on_auth(self):
        response = requests.get(f'{self.server_url}/auth')
        self.assertEqual(response.status_code, 405)

    #test - send invalid method to JWKS endpt return 405
    def test_unsupported_method_on_jwks(self):
        response = requests.post(f'{self.server_url}/.well-known/jwks.json')
        self.assertEqual(response.status_code, 405)

    #test - req an unknown endpt returns 404
    def test_404_for_unknown_endpoint(self):
        response = requests.get(f'{self.server_url}/nonexistent')
        self.assertEqual(response.status_code, 404)

if __name__ == '__main__':
    unittest.main()
