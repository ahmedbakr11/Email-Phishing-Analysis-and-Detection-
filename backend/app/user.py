from flask_restx import Namespace, Resource, fields
from flask import request
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash

from .models import User
from . import require_admin

user_ns = Namespace("user", description="A nampespace for user")


# CRUD
# Model FOr Serializer
user_model = user_ns.model(
    "User",
    {
        "id": fields.Integer(),
        "fullname": fields.String(),
        "username": fields.String(),
        "email": fields.String(),
        "password": fields.String(),
        "role": fields.String(),
        "failed_login_attempts": fields.Integer(),
        "suspended": fields.Boolean(),
    },
)


# Simple hello endpoint
@user_ns.route("/hello")
class Hello(Resource):
    def get(self):
        return {"status": "work"}

    ###################################################


@user_ns.route("/users")
class UserResource(Resource):

    # Get all users data
    @user_ns.marshal_list_with(user_model)
    @jwt_required()
    def get(self):
        """Get all users"""
        require_admin()
        users = User.query.all()

        sanitized_users = []
        for user in users:
            sanitized_users.append(
                {
                    "id": user.id,
                    "fullname": user.fullname,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role,
                    "failed_login_attempts": user.failed_login_attempts,
                    "suspended": user.suspended,
                }
            )
        return sanitized_users

    ###################################################

    # Create new user
    @user_ns.marshal_with(user_model)
    @user_ns.expect(user_model)
    @jwt_required()
    def post(self):
        """Create a new user"""
        require_admin()
        data = request.get_json()
        username = data.get("username")
        email = data.get("email")

        if User.query.filter(User.username == username).first():
            user_ns.abort(
                409, error="User already exists"
            )  ## TO return js cuz we use marshal
        if User.query.filter(User.email == email).first():
            user_ns.abort(409, error="Email already exists")

        new_user = User(
            fullname=data.get("fullname"),
            username=data.get("username"),
            email=data.get("email"),
            password=generate_password_hash(data.get("password")),
        )
        new_user.save()
        return "User added", 201

    ###################################################


# Get user data by id
@user_ns.route("/users/<int:id>")
class UserDetailResource(Resource):
    @user_ns.marshal_with(user_model)
    @jwt_required()
    def get(self, id):
        """Get a user by id"""
        user = User.query.get_or_404(id)
        sanitized_users = []
        
        sanitized_users.append(
            {
                "id": user.id,
                "fullname": user.fullname,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "failed_login_attempts": user.failed_login_attempts,
                "suspended": user.suspended,
            }
        )
        return sanitized_users

    ###################################################

    # Update user data by id
    @user_ns.marshal_with(user_model)
    @user_ns.expect(user_model)
    @jwt_required()
    def put(self, id):
        """Update a user by id"""
        require_admin()
        user_to_update = User.query.get_or_404(id)
        data = request.get_json()

        fullname = data.get("fullname")
        username = data.get("username")
        email = data.get("email")
        role = data.get("role")
        suspended = data.get("suspended")

        if User.query.filter(User.username == username, User.id != id).first():
            user_ns.abort(
                409, error="User already exists"
            )  ## TO return js cuz we use marshal
        if User.query.filter(User.email == email, User.id != id).first():
            user_ns.abort(409, error="Email already exists")

        password = data.get("password")

        user_to_update.update(
            fullname,
            username,
            email,
            (generate_password_hash(password) if password else user_to_update.password),
            (role if role else user_to_update.role),
            (suspended if suspended is not None else user_to_update.suspended),
        )

        if suspended is not None:
            if suspended:
                user_to_update.suspended = True
                user_to_update.save()
            else:
                user_to_update.reset_login_state()
        
        

        return user_to_update

    ###################################################

    # Delete user data by id
    @user_ns.marshal_with(user_model)
    @jwt_required()
    def delete(self, id):
        """Delete a a user by id"""
        require_admin()
        user_to_delete = User.query.get_or_404(id)
        current_user_id = get_jwt_identity()
        if current_user_id is not None and str(user_to_delete.id) == str(
            current_user_id
        ):
            user_ns.abort(400, error="Admins cannot delete their own account")

        user_to_delete.delete()
        return user_to_delete
