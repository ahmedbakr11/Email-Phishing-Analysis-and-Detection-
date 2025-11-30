from flask_restx import Namespace, Resource
from flask_jwt_extended import jwt_required

user_ns = Namespace("user", description="A nampespace for user")

ADMIN_LOCKED = {"error": "User management is disabled in admin-only mode"}

# Simple hello endpoint
@user_ns.route("/hello")
class Hello(Resource):
    def get(self):
        return {"status": "work"}

    ###################################################


@user_ns.route("/users")
class UserResource(Resource):

    # Get all users data
    @jwt_required()
    def get(self):
        """Disabled in admin-only mode"""
        return ADMIN_LOCKED, 403

    ###################################################

    # Create new user
    @jwt_required()
    def post(self):
        """Disabled in admin-only mode"""
        return ADMIN_LOCKED, 403

    ###################################################


# Get user data by id
@user_ns.route("/users/<int:id>")
class UserDetailResource(Resource):
    @jwt_required()
    def get(self, id):
        """Disabled in admin-only mode"""
        return ADMIN_LOCKED, 403

    ###################################################

    # Update user data by id
    @jwt_required()
    def put(self, id):
        """Disabled in admin-only mode"""
        return ADMIN_LOCKED, 403

    ###################################################

    # Delete user data by id
    @jwt_required()
    def delete(self, id):
        """Disabled in admin-only mode"""
        return ADMIN_LOCKED, 403
