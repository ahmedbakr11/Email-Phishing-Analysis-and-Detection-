from flask import request
from flask_restx import Resource, Namespace, fields
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
)

from .models import User
from .security import DecryptionError, decrypt_sensitive_fields, get_public_key_pem


auth_ns = Namespace("auth", description="A namespace for our Authentication")


signup_model = auth_ns.model(
    "SignUp",
    {
        "fullname": fields.String(),
        "username": fields.String(),
        "email": fields.String(),
        "password": fields.String(),
    },
)


login_model = auth_ns.model(
    "LoginResource",
    {
        "username": fields.String(),
        "password": fields.String(),
    },
)


@auth_ns.route("/signup")
class SignUp(Resource):

    @auth_ns.expect(signup_model)
    def post(self):
        data = request.get_json() or {}

        try:
            decrypt_sensitive_fields(
                data,
                ("fullname", "username", "email", "password"),
            )
        except DecryptionError:
            return ({"error": "Unable to decrypt credentials"}), 400
        fullname = data.get("fullname")
        username = data.get("username")
        email = data.get("email")
        password = generate_password_hash(data.get("password"))

        if User.query.filter(User.username == username).first():
            return ({"error": "User already exists"}), 409

        if User.query.filter(User.email == email).first():
            return ({"error": "Email already exists"}), 409

        if not username or not email or not password or not fullname:
            return ({"error": "Missing fields"}), 400

        new_user = User(
            fullname=data.get("fullname"),
            username=data.get("username"),
            email=data.get("email"),
            password=generate_password_hash(data.get("password")),
        )
        new_user.save()
        return ({"message": "User created successfully"}), 201


###################################################################################


@auth_ns.route("/login")
@auth_ns.expect(login_model)
class LoginResource(Resource):

    def post(self):

        data = request.get_json(login_model) or {}

        try:
            decrypt_sensitive_fields(
                data,
                ("username", "password"),
            )
        except DecryptionError:
            return ({"message": "Unable to decrypt credentials"}), 400

        ## Gets login data from front-end request
        username = data.get("username")
        password = data.get("password")

        db_user = User.query.filter_by(
            username=username
        ).first()  ## Checks if the user exists in the database

        if not db_user:
            return {"message": "Wrong username or password"}, 401

        if db_user.suspended:
            return {
                "message": "Account is suspended. Please contact an administrator."
            }, 403

        if not check_password_hash(db_user.password, password):
            db_user.record_failed_login()
            status = 403 if db_user.suspended else 401
            msg = (
                "Account is suspended. Please contact an administrator."
                if db_user.suspended
                else "Wrong username or password"
            )
            return {"message": msg}, status

        db_user.reset_login_state()

        claims = {"role": db_user.role}
        access_token = create_access_token(
            identity=str(db_user.id),
            additional_claims=claims,
            expires_delta=False,
        )
        refresh_token = create_refresh_token(
            identity=str(db_user.id),
            additional_claims=claims,
        )

        return {
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": db_user.id,
                "username": db_user.username,
                "fullname": db_user.fullname,
                "email": db_user.email,
                "role": db_user.role,
            },
        }, 200


###########################################################################################


@auth_ns.route("/public-key")
class PublicKeyResource(Resource):
    def get(self):
        return {"public_key": get_public_key_pem()}, 200


###########################################################################################


@auth_ns.route("/refresh")
class ResfreshResourse(Resource):
    @jwt_required(refresh=True)
    def post(self):

        current_user = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user)
        return {"access_token": new_access_token}, 200
