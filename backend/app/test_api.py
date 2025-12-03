import unittest

from flask_restx import Api

from . import create_app
from .auth import auth_ns
from .extensions import db
from ..config import testconfig


class APITestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(testconfig)
        api = Api(self.app, doc="/docs", prefix="/api")
        api.add_namespace(auth_ns)
        self.client = self.app.test_client(self)

        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def _signup(self, username="testuser"):
        return self.client.post(
            "/api/auth/signup",
            json={
                "fullname": "Test User",
                "username": username,
                "email": f"{username}@example.com",
                "password": "password123",
            },
        )

    def test_signup_creates_user(self):
        response = self._signup()
        self.assertEqual(response.status_code, 201)

    def test_login_and_refresh(self):
        self._signup()
        login_response = self.client.post(
            "/api/auth/login",
            json={"username": "testuser", "password": "password123"},
        )
        self.assertEqual(login_response.status_code, 200)

        data = login_response.get_json() or {}
        self.assertIn("access_token", data)
        self.assertIn("refresh_token", data)

        refresh_response = self.client.post(
            "/api/auth/refresh",
            headers={"Authorization": f"Bearer {data['refresh_token']}"},
        )
        self.assertEqual(refresh_response.status_code, 200)

    def test_public_key_available(self):
        response = self.client.get("/api/auth/public-key")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json().get("public_key"))


if __name__ == "__main__":
    unittest.main()
