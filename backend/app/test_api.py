### To run this file with output python check each test -m backend.app.test_api -v

import unittest
from flask_restx import Api

from .extensions import db
from . import create_app
from ..config import testconfig
from .auth import auth_ns
from .user import user_ns


class APITestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(
            testconfig
        )  # we need to add ConfigSet for Create_app in main file
        api = Api(self.app, doc="/docs", prefix="/api")
        api.add_namespace(user_ns)
        api.add_namespace(auth_ns)
        self.client = self.app.test_client(self)

        with self.app.app_context():
            db.create_all()

    ####################################################################################
    ## Test Hello
    def test_hello(self):
        hello_response = self.client.get("/api/user/hello")
        json = hello_response.get_json()
        # print(json)
        self.assertEqual(json, {"status": "work"})

    ####################################################################################
    # Test Signup
    def test_signup(self):
        signup_response = self.client.post(
            "/api/auth/signup",
            json={
                "username": "testuser",
                "email": "testuser@test.com",
                "password": "password",
            },
        )
        status_code = signup_response.status_code
        self.assertEqual(status_code, 201)

    ####################################################################################
    # Test login
    def test_login(self):
        self.client.post(
            "/api/auth/signup",
            json={
                "username": "testuser",
                "email": "testuser@test.com",
                "password": "password",
            },
        )

        login_response = self.client.post(
            "/api/auth/login",
            json={
                "username": "testuser",
                "password": "password",
            },
        )

        status_code = login_response.status_code
        self.assertEqual(status_code, 200)
        json = login_response.json
        # print(json)

    ####################################################################################
    # Test Refresh
    def test_refresh_token(self):
        self.client.post(
            "/api/auth/signup",
            json={
                "username": "testuser",
                "email": "testuser@test.com",
                "password": "password",
            },
        )
        login_response = self.client.post(
            "/api/auth/login",
            json={
                "username": "testuser",
                "password": "password",
            },
        )

        refresh_token = login_response.json["refresh_token"]
        refresh_token_response = self.client.post(
            "/api/auth/refresh",
            headers={"Authorization": f"Bearer {refresh_token}"},
        )

        status_code = refresh_token_response.status_code
        # print(refresh_token_response.json)
        self.assertEqual(status_code, 200)

    ####################################################################################
    # Test get all users
    def test_get_all_user(self):
        self.client.post(
            "/api/auth/signup",
            json={
                "username": "testuser",
                "email": "testuser@test.com",
                "password": "password",
            },
        )
        self.client.post(
            "/api/auth/signup",
            json={
                "username": "testuser2",
                "email": "testuser2@test.com",
                "password": "password",
            },
        )

        login_response = self.client.post(
            "/api/auth/login",
            json={
                "username": "testuser",
                "password": "password",
            },
        )
        access_token = login_response.json["access_token"]
        get_all_user_response = self.client.get(
            "/api/user/users",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        status_code = get_all_user_response.status_code
        # print(get_all_user_response.json)
        self.assertEqual(status_code, 200)

    ####################################################################################
    # Test get one user
    def test_get_one_user(self):
        self.client.post(
            "/api/auth/signup",
            json={
                "username": "testuser",
                "email": "testuser@test.com",
                "password": "password",
            },
        )
        self.client.post(
            "/api/auth/signup",
            json={
                "username": "testuser2",
                "email": "testuser2@test.com",
                "password": "password",
            },
        )

        login_response = self.client.post(
            "/api/auth/login",
            json={
                "username": "testuser",
                "password": "password",
            },
        )
        access_token = login_response.json["access_token"]
        id = 3
        get_one_user_response = self.client.get(
            f"/api/user/users/{id}",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        status_code = get_one_user_response.status_code
        # print(get_one_user_response.json)
        self.assertEqual(status_code, 404)

    ####################################################################################
    # Test create user
    def test_create_user(self):
        self.client.post(
            "/api/auth/signup",
            json={
                "username": "testuser",
                "email": "testuser@test.com",
                "password": "password",
            },
        )

        login_response = self.client.post(
            "/api/auth/login",
            json={
                "username": "testuser",
                "password": "password",
            },
        )
        access_token = login_response.json["access_token"]

        create_user_response = self.client.post(
            "/api/user/users",
            json={"username": "ragab", "email": "ragab@gmail.com", "password": "alo"},
            headers={"Authorization": f"Bearer {access_token}"},
        )

        status_code = create_user_response.status_code
        # print(create_user_response.json)
        self.assertEqual(status_code, 201)

    ####################################################################################
    # Test update user
    def test_update_user(self):
        self.client.post(
            "/api/auth/signup",
            json={
                "username": "testuser",
                "email": "testuser@test.com",
                "password": "password",
            },
        )

        login_response = self.client.post(
            "/api/auth/login",
            json={
                "username": "testuser",
                "password": "password",
            },
        )
        access_token = login_response.json["access_token"]

        self.client.post(
            "/api/user/users",
            json={"username": "ragab", "email": "ragab@gmail.com", "password": "alo"},
            headers={"Authorization": f"Bearer {access_token}"},
        )

        id = 1
        update_response = self.client.put(
            f"api/user/users/{id}",
            json={
                "username": "ragab",
                "email": "ragab@gmail.com",
                "password": "alo",
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )

        status_code = update_response.status_code
        self.assertEqual(status_code, 409)

    ####################################################################################
    # Test update user
    def test_delete_user(self):
        self.client.post(
            "/api/auth/signup",
            json={
                "username": "testuser",
                "email": "testuser@test.com",
                "password": "password",
            },
        )

        login_response = self.client.post(
            "/api/auth/login",
            json={
                "username": "testuser",
                "password": "password",
            },
        )
        access_token = login_response.json["access_token"]

        self.client.post(
            "/api/user/users",
            json={"username": "ragab", "email": "ragab@gmail.com", "password": "alo"},
            headers={"Authorization": f"Bearer {access_token}"},
        )

        id = 1
        delete_response = self.client.delete(
            f"api/user/users/{id}",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        status_code = delete_response.status_code
        # print(delete_response.json)
        self.assertEqual(status_code, 200)

    ####################################################################################

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()


if __name__ == "__main__":
    unittest.main()
